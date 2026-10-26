//! OAuth install: the authorization code grant with expiring offline tokens.
//!
//! 1. `GET /shopify/auth?shop={shop}` checks the shop (and the `hmac` when
//!    Shopify sent one), sets a state cookie, and redirects to the Shopify
//!    authorize page.
//! 2. Shopify redirects back to `GET /shopify/auth/callback`. The route
//!    checks the query HMAC (401), the shop (400), and the state and shop
//!    against the cookie (403). Then it exchanges the code for a token,
//!    checks the granted scopes (403), stores the token, runs the install
//!    handler, and redirects to `after_install_path` with `shop={shop}`.
//!
//! The `__Host-` state cookie binds the flow to the browser and to the
//! shop. The flow keeps no server state, so it works across replicas.
//!
//! The `shop` value in the final redirect is not signed. The landing route
//! must not trust it to open a session.
//!
//! Both routes answer 404 when OAuth is off.

use std::collections::HashSet;
use std::sync::Arc;

use autumn_web::reexports::axum::body::Body;
use autumn_web::reexports::axum::extract::RawQuery;
use autumn_web::reexports::axum::response::Response;
use autumn_web::reexports::http::{HeaderMap, StatusCode, header};
use autumn_web::{AppState, AutumnResult, State, get, public, routes};
use serde::Deserialize;
use subtle::ConstantTimeEq as _;

use crate::config::ShopifyConfig;
use crate::error::{Error, Result};
use crate::plugin::{InstallContext, Keeper, Shopify, ShopifyRuntime};
use crate::tokens::ShopToken;
use crate::types::ShopDomain;

/// The state cookie name. The `__Host-` prefix stops other subdomains
/// from setting it.
pub const STATE_COOKIE: &str = "__Host-shopify_oauth_state";
/// The install route path.
pub const AUTH_PATH: &str = "/shopify/auth";
/// The callback route path.
pub const CALLBACK_PATH: &str = "/shopify/auth/callback";
/// The state cookie lives for 10 minutes.
pub const STATE_COOKIE_MAX_AGE_SECS: u32 = 600;
/// The number of random bytes in a state nonce.
pub const NONCE_BYTES: usize = 16;

/// The cookie attributes. A `__Host-` cookie must have `Path=/`, `Secure`,
/// and no `Domain`.
const COOKIE_ATTRIBUTES: &str = "Path=/; HttpOnly; Secure; SameSite=Lax";

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
/// Returns [`Error::InvalidRequest`] when a key appears two times.
pub(crate) fn parse_query(raw: Option<&str>) -> Result<Vec<(String, String)>> {
    let mut seen = HashSet::new();
    let mut pairs = Vec::new();
    for (key, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        if !seen.insert(key.clone()) {
            return Err(Error::InvalidRequest(format!(
                "query parameter {key:?} appears two times"
            )));
        }
        pairs.push((key.into_owned(), value.into_owned()));
    }
    Ok(pairs)
}

/// The value of cookie `name` in the `Cookie` headers.
///
/// Returns `None` when the cookie is missing or appears more than once.
pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| value);
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

/// The `Set-Cookie` value that stores `nonce` and `shop`.
pub(crate) fn state_cookie(nonce: &str, shop: &ShopDomain) -> String {
    format!(
        "{STATE_COOKIE}={nonce}.{shop}; Max-Age={STATE_COOKIE_MAX_AGE_SECS}; {COOKIE_ATTRIBUTES}"
    )
}

/// The `Set-Cookie` value that clears the state cookie.
pub(crate) fn clear_state_cookie() -> String {
    format!("{STATE_COOKIE}=; Max-Age=0; {COOKIE_ATTRIBUTES}")
}

/// The token endpoint answer.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    scope: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    refresh_token_expires_in: Option<i64>,
}

/// An OAuth error body, for example `{"error": "invalid_client"}`.
#[derive(Debug, Deserialize)]
struct OAuthError {
    error: Option<String>,
}

/// Exchange an authorization code for an expiring offline token.
///
/// # Errors
///
/// Returns [`Error::Http`] or [`Error::ShopifyApi`] when the exchange
/// fails.
pub(crate) async fn exchange_code(
    keeper: &Keeper,
    shop: &ShopDomain,
    code: &str,
    now: i64,
) -> Result<ShopToken> {
    let response = post_token_form(
        keeper,
        shop,
        &[
            ("client_id", keeper.api_key()?),
            ("client_secret", keeper.secret()),
            ("code", code),
            ("expiring", "1"),
        ],
    )
    .await?;
    if !response.status().is_success() {
        return Err(crate::client::api_error(response).await);
    }
    let mut token = read_token(response, now).await?;
    token.installed_at = Some(now);
    Ok(token)
}

/// Refresh an expiring token.
///
/// Only a 401 that is not `invalid_client` means "the refresh token is
/// dead". Any other failure keeps the stored token.
///
/// # Errors
///
/// Returns [`Error::Reauthorize`] when Shopify refuses the refresh token,
/// or [`Error::Http`] / [`Error::ShopifyApi`] on other failures.
pub(crate) async fn refresh_token(
    keeper: &Keeper,
    shop: &ShopDomain,
    refresh: &str,
    now: i64,
) -> Result<ShopToken> {
    let response = post_token_form(
        keeper,
        shop,
        &[
            ("client_id", keeper.api_key()?),
            ("client_secret", keeper.secret()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
        ],
    )
    .await?;
    let status = response.status();
    if status.is_success() {
        return read_token(response, now).await;
    }
    let err = crate::client::api_error(response).await;
    if status == StatusCode::UNAUTHORIZED
        && let Error::ShopifyApi { body, .. } = &err
    {
        let code = serde_json::from_str::<OAuthError>(body)
            .ok()
            .and_then(|e| e.error);
        if code.as_deref() != Some("invalid_client") {
            return Err(Error::Reauthorize(shop.to_string()));
        }
    }
    Err(err)
}

/// POST a form to `{shop}/admin/oauth/access_token`.
async fn post_token_form(
    keeper: &Keeper,
    shop: &ShopDomain,
    form: &[(&str, &str)],
) -> Result<reqwest::Response> {
    keeper
        .http()
        .post(format!(
            "{}/admin/oauth/access_token",
            keeper.admin_origin(shop)
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
    let answer: TokenResponse = serde_json::from_slice(&bytes)
        .map_err(|_| Error::UnexpectedResponse("the token answer is not valid".to_owned()))?;
    let mut token = ShopToken::non_expiring(answer.access_token, answer.scope);
    token.expires_at = answer.expires_in.map(|secs| now.saturating_add(secs));
    token.refresh_token = answer.refresh_token;
    token.refresh_token_expires_at = answer
        .refresh_token_expires_in
        .map(|secs| now.saturating_add(secs));
    Ok(token)
}

/// The install route.
#[get("/auth")]
#[public]
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
    // Shopify signs the request when the merchant starts from the admin.
    // A typed URL has no `hmac`.
    if param(&params, "hmac").is_some() {
        crate::verify::verify_query(runtime.secrets(), &params)?;
    }
    let shop = ShopDomain::parse(param(&params, "shop").unwrap_or_default())?;
    let mut nonce = [0u8; NONCE_BYTES];
    state.entropy().fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    let location = authorize_url(runtime.config(), &shop, &nonce)?;
    tracing::info!(shop = %shop, "shopify install started");
    redirect(&location, &state_cookie(&nonce, &shop))
}

/// The callback route.
#[get("/auth/callback")]
#[public]
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
    check_state(headers, param(&params, "state").unwrap_or_default(), &shop)?;
    let code = param(&params, "code")
        .filter(|code| !code.is_empty())
        .ok_or_else(|| Error::InvalidRequest("missing code parameter".to_owned()))?;

    let now = state.clock().now().timestamp();
    let token = exchange_code(runtime.keeper(), &shop, code, now).await?;
    let missing = missing_scopes(&runtime.config().scopes, &token.scopes());
    if !missing.is_empty() {
        return Err(Error::ScopeMismatch { missing });
    }
    let scope = token.scope.clone();
    runtime.keeper().store_install(&shop, token).await?;
    tracing::info!(shop = %shop, "shopify install complete");

    if let Some(handler) = runtime.on_install() {
        let ctx = InstallContext {
            shop: shop.clone(),
            scope,
            state: state.clone(),
            shopify: Shopify::from_runtime(Arc::clone(&runtime), state.clone()),
        };
        handler(ctx).await.map_err(|err| {
            tracing::error!(shop = %shop, error = %err, "shopify install handler failed");
            Error::Store(format!("the install handler failed: {err}"))
        })?;
    }

    redirect(
        &after_install_location(&runtime.config().after_install_path, &shop),
        &clear_state_cookie(),
    )
}

/// Compare the `state` parameter and the shop with the state cookie, in
/// constant time.
fn check_state(headers: &HeaderMap, sent: &str, shop: &ShopDomain) -> Result<()> {
    let cookie = cookie_value(headers, STATE_COOKIE).unwrap_or_default();
    let (kept_nonce, kept_shop) = cookie.split_once('.').unwrap_or_default();
    let nonce_ok = !sent.is_empty() && bool::from(sent.as_bytes().ct_eq(kept_nonce.as_bytes()));
    if nonce_ok && kept_shop == shop.as_str() {
        Ok(())
    } else {
        Err(Error::StateMismatch)
    }
}

/// `after_install_path` with `shop={shop}` added to its query.
pub(crate) fn after_install_location(path: &str, shop: &ShopDomain) -> String {
    let pair = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("shop", shop.as_str())
        .finish();
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}{pair}")
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
        .map_err(|err| Error::InvalidRequest(format!("the redirect does not build: {err}")))
}

/// The OAuth routes, for the plugin to mount under `/shopify`.
pub(crate) fn oauth_routes() -> Vec<autumn_web::Route> {
    routes![install_route, callback_route]
}

#[cfg(test)]
mod tests;
