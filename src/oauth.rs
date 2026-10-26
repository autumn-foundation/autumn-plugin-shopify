//! OAuth install: the authorization code grant with expiring offline tokens.
//!
//! 1. `GET /shopify/auth?shop={shop}` checks the shop, sets a state cookie,
//!    and redirects to Shopify's authorize page.
//! 2. Shopify redirects back to `GET /shopify/auth/callback`. The route
//!    checks the query HMAC (401), the shop (400), and the state against
//!    the cookie (403). Then it exchanges the code for a token, checks the
//!    granted scopes (403), stores the token, and redirects to
//!    `after_install_path?shop={shop}`.
//!
//! The state cookie binds the flow to the browser. The flow keeps no server
//! state, so it works across replicas.
//!
//! Both routes answer 404 when OAuth is off.

use std::collections::HashSet;
use std::sync::Arc;

use autumn_web::reexports::axum::body::Body;
use autumn_web::reexports::axum::extract::RawQuery;
use autumn_web::reexports::axum::response::Response;
use autumn_web::reexports::http::{HeaderMap, StatusCode, header};
use autumn_web::{AppState, AutumnResult, State, get, routes};
use serde::Deserialize;
use subtle::ConstantTimeEq as _;

use crate::config::ShopifyConfig;
use crate::error::{Error, Result};
use crate::plugin::ShopifyRuntime;
use crate::tokens::ShopToken;
use crate::types::ShopDomain;

/// The state cookie name.
pub const STATE_COOKIE: &str = "shopify_oauth_state";
/// The install route path.
pub const AUTH_PATH: &str = "/shopify/auth";
/// The callback route path.
pub const CALLBACK_PATH: &str = "/shopify/auth/callback";
/// The state cookie lives for 10 minutes.
pub const STATE_COOKIE_MAX_AGE_SECS: u32 = 600;
/// The number of random bytes in a state nonce.
pub const NONCE_BYTES: usize = 16;

/// Build the Shopify authorize URL for `shop`.
///
/// # Errors
///
/// Returns [`Error::OAuthDisabled`] when OAuth is off, or
/// [`Error::Config`] when `api_key` is missing.
pub fn authorize_url(config: &ShopifyConfig, shop: &ShopDomain, nonce: &str) -> Result<String> {
    let redirect_uri = config.redirect_uri().ok_or(Error::OAuthDisabled)?;
    let api_key = config
        .api_key
        .as_deref()
        .ok_or_else(|| Error::Config("OAuth needs [shopify] api_key".to_owned()))?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", api_key)
        .append_pair("scope", &config.scopes.join(","))
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", nonce)
        .finish();
    Ok(format!("https://{shop}/admin/oauth/authorize?{query}"))
}

/// The requested scopes that `granted` does not cover.
///
/// A granted `write_x` covers a requested `read_x`.
#[must_use]
pub fn missing_scopes(requested: &[String], granted: &[&str]) -> Vec<String> {
    let granted: HashSet<&str> = granted.iter().copied().collect();
    requested
        .iter()
        .filter(|scope| {
            let covered_by_write = scope
                .strip_prefix("read_")
                .is_some_and(|rest| granted.contains(format!("write_{rest}").as_str()));
            !granted.contains(scope.as_str()) && !covered_by_write
        })
        .cloned()
        .collect()
}

/// Decode a query string into pairs.
///
/// # Errors
///
/// Returns [`Error::InvalidRequest`] when a key appears twice.
pub(crate) fn parse_query(raw: Option<&str>) -> Result<Vec<(String, String)>> {
    let mut seen = HashSet::new();
    let mut pairs = Vec::new();
    for (key, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        if !seen.insert(key.clone()) {
            return Err(Error::InvalidRequest(format!(
                "query parameter {key:?} appears twice"
            )));
        }
        pairs.push((key.into_owned(), value.into_owned()));
    }
    Ok(pairs)
}

/// The value of cookie `name` in the `Cookie` headers.
pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// The `Set-Cookie` value that stores `nonce`.
pub(crate) fn state_cookie(nonce: &str) -> String {
    format!(
        "{STATE_COOKIE}={nonce}; {COOKIE_ATTRIBUTES_PATH}; Max-Age={STATE_COOKIE_MAX_AGE_SECS}; {COOKIE_ATTRIBUTES_FLAGS}"
    )
}

/// The `Set-Cookie` value that clears the state cookie.
pub(crate) fn clear_state_cookie() -> String {
    format!("{STATE_COOKIE}=; {COOKIE_ATTRIBUTES_PATH}; Max-Age=0; {COOKIE_ATTRIBUTES_FLAGS}")
}

/// The cookie path: the browser sends it only to the OAuth routes.
const COOKIE_ATTRIBUTES_PATH: &str = "Path=/shopify/auth";
/// The cookie flags.
const COOKIE_ATTRIBUTES_FLAGS: &str = "HttpOnly; Secure; SameSite=Lax";

/// The token endpoint answer.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    scope: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    refresh_token_expires_in: Option<i64>,
}

/// Exchange an authorization code for an expiring offline token.
///
/// # Errors
///
/// Returns [`Error::Http`] or [`Error::ShopifyApi`] when the exchange
/// fails.
pub(crate) async fn exchange_code(
    runtime: &ShopifyRuntime,
    shop: &ShopDomain,
    code: &str,
    now: i64,
) -> Result<ShopToken> {
    let (client_id, secret) = credentials(runtime)?;
    let response = post_token_form(
        runtime,
        shop,
        &[
            ("client_id", client_id),
            ("client_secret", secret),
            ("code", code),
            ("expiring", "1"),
        ],
    )
    .await?;
    if !response.status().is_success() {
        return Err(crate::client::api_error(response).await);
    }
    read_token(response, now).await
}

/// Refresh an expiring token.
///
/// # Errors
///
/// Returns [`Error::Reauthorize`] when Shopify refuses the refresh token
/// (400 or 401), or [`Error::Http`] / [`Error::ShopifyApi`] on other
/// failures.
pub(crate) async fn refresh_token(
    runtime: &ShopifyRuntime,
    shop: &ShopDomain,
    refresh: &str,
    now: i64,
) -> Result<ShopToken> {
    let (client_id, secret) = credentials(runtime)?;
    let response = post_token_form(
        runtime,
        shop,
        &[
            ("client_id", client_id),
            ("client_secret", secret),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
        ],
    )
    .await?;
    let status = response.status();
    if status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED {
        return Err(Error::Reauthorize(shop.to_string()));
    }
    if !status.is_success() {
        return Err(crate::client::api_error(response).await);
    }
    read_token(response, now).await
}

/// The client id and current secret for the token endpoint.
fn credentials(runtime: &ShopifyRuntime) -> Result<(&str, &str)> {
    let client_id = runtime
        .config()
        .api_key
        .as_deref()
        .ok_or_else(|| Error::Config("token calls need [shopify] api_key".to_owned()))?;
    Ok((client_id, runtime.secrets().current()))
}

/// POST a form to `{shop}/admin/oauth/access_token`.
async fn post_token_form(
    runtime: &ShopifyRuntime,
    shop: &ShopDomain,
    form: &[(&str, &str)],
) -> Result<reqwest::Response> {
    runtime
        .http()
        .post(format!(
            "{}/admin/oauth/access_token",
            runtime.admin_origin(shop)
        ))
        .header(header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await
        .map_err(Error::Http)
}

/// Read a token answer into a [`ShopToken`] with absolute expiry times.
async fn read_token(response: reqwest::Response, now: i64) -> Result<ShopToken> {
    let bytes = response.bytes().await.map_err(Error::Http)?;
    let answer: TokenResponse = serde_json::from_slice(&bytes).map_err(|_| Error::ShopifyApi {
        status: 200,
        body: "the token answer is not valid".to_owned(),
    })?;
    Ok(ShopToken {
        access_token: answer.access_token,
        scope: answer.scope,
        expires_at: answer.expires_in.map(|secs| now.saturating_add(secs)),
        refresh_token: answer.refresh_token,
        refresh_token_expires_at: answer
            .refresh_token_expires_in
            .map(|secs| now.saturating_add(secs)),
    })
}

/// The install route.
#[get("/auth")]
async fn install_route(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> AutumnResult<Response> {
    install(&state, query.as_deref()).map_err(|err| err.to_autumn_error())
}

/// The install flow.
fn install(state: &AppState, query: Option<&str>) -> Result<Response> {
    let runtime = oauth_runtime(state)?;
    let params = parse_query(query)?;
    let shop = ShopDomain::parse(param(&params, "shop").unwrap_or_default())?;
    let mut nonce = [0u8; NONCE_BYTES];
    state.entropy().fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    let location = authorize_url(runtime.config(), &shop, &nonce)?;
    tracing::info!(shop = %shop, "shopify install started");
    redirect(&location, &state_cookie(&nonce))
}

/// The callback route.
#[get("/auth/callback")]
async fn callback_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> AutumnResult<Response> {
    callback(&state, &headers, query.as_deref())
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "shopify install callback failed");
            err.to_autumn_error()
        })
}

/// The callback flow. The checks run in a fixed order: HMAC, shop, state,
/// code. No token call runs before all four pass.
async fn callback(state: &AppState, headers: &HeaderMap, query: Option<&str>) -> Result<Response> {
    let runtime = oauth_runtime(state)?;
    let params = parse_query(query)?;
    crate::verify::verify_query(runtime.secrets(), &params)?;
    let shop = ShopDomain::parse(param(&params, "shop").unwrap_or_default())?;
    let sent = param(&params, "state").unwrap_or_default();
    let kept = cookie_value(headers, STATE_COOKIE).unwrap_or_default();
    if sent.is_empty() || !bool::from(sent.as_bytes().ct_eq(kept.as_bytes())) {
        return Err(Error::StateMismatch);
    }
    let code = param(&params, "code")
        .filter(|code| !code.is_empty())
        .ok_or_else(|| Error::InvalidRequest("missing code parameter".to_owned()))?;

    let now = state.clock().now().timestamp();
    let token = exchange_code(&runtime, &shop, code, now).await?;
    let missing = missing_scopes(&runtime.config().scopes, &token.scopes());
    if !missing.is_empty() {
        return Err(Error::ScopeMismatch { missing });
    }
    runtime.token_store().put(&shop, token).await?;
    tracing::info!(shop = %shop, "shopify install complete");

    let after = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("shop", shop.as_str())
        .finish();
    redirect(
        &format!("{}?{after}", runtime.config().after_install_path),
        &clear_state_cookie(),
    )
}

/// The runtime, when OAuth is on.
fn oauth_runtime(state: &AppState) -> Result<Arc<ShopifyRuntime>> {
    let runtime = state
        .extension::<ShopifyRuntime>()
        .ok_or(Error::MissingRuntime)?;
    if runtime.config().oauth_enabled() {
        Ok(runtime)
    } else {
        Err(Error::OAuthDisabled)
    }
}

/// The value of query parameter `key`.
fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value.as_str())
}

/// A 302 redirect that sets one cookie.
fn redirect(location: &str, cookie: &str) -> Result<Response> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, cookie)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .map_err(|err| Error::InvalidRequest(format!("redirect does not build: {err}")))
}

/// The OAuth routes, for the plugin to mount under `/shopify`.
pub(crate) fn oauth_routes() -> Vec<autumn_web::Route> {
    routes![install_route, callback_route]
}

#[cfg(test)]
mod tests;
