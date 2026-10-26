//! Admin GraphQL API client.
//!
//! [`ShopifyClient`] posts GraphQL documents to
//! `https://{shop}/admin/api/{version}/graphql.json` with the
//! `X-Shopify-Access-Token` header.
//!
//! Shopify does not run a throttled request, so a retry is safe. The
//! client retries a `THROTTLED` GraphQL error and an HTTP 429, up to
//! [`RetryPolicy::max_retries`]. It does not retry other failures: a
//! mutation is not always idempotent.

use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::types::{ApiVersion, ShopDomain, Topic};

/// Request timeout for Shopify calls.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest error body the client keeps, in chars.
pub(crate) const MAX_ERROR_BODY_CHARS: usize = 500;
/// Header that carries the Admin API access token.
pub const ACCESS_TOKEN_HEADER: &str = "x-shopify-access-token";

/// How the client retries throttled calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// The number of retries after the first try.
    pub max_retries: u32,
    /// The longest wait before one retry.
    pub max_wait: Duration,
}

impl RetryPolicy {
    /// Make a policy.
    #[must_use]
    pub const fn new(max_retries: u32, max_wait: Duration) -> Self {
        Self {
            max_retries,
            max_wait,
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            max_wait: Duration::from_secs(10),
        }
    }
}

/// The shop record from [`ShopifyClient::shop_info`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ShopInfo {
    /// The shop name.
    pub name: String,
    /// The `*.myshopify.com` domain.
    pub myshopify_domain: String,
}

/// An Admin GraphQL client for one shop and one token.
///
/// A clone is cheap. `Debug` redacts the token.
#[derive(Clone)]
pub struct ShopifyClient {
    http: reqwest::Client,
    shop: ShopDomain,
    base_url: String,
    api_version: ApiVersion,
    token: String,
    retry: RetryPolicy,
}

impl std::fmt::Debug for ShopifyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopifyClient")
            .field("shop", &self.shop)
            .field("base_url", &self.base_url)
            .field("api_version", &self.api_version)
            .field("token", &"<redacted>")
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl ShopifyClient {
    /// Make a client for `shop` with a new HTTP connection pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the token is blank, or
    /// [`Error::Http`] when the HTTP client does not build.
    pub fn new(
        shop: ShopDomain,
        api_version: ApiVersion,
        access_token: impl Into<String>,
    ) -> Result<Self> {
        let token = access_token.into();
        if token.trim().is_empty() {
            return Err(Error::Config("the access token is blank".to_owned()));
        }
        Ok(Self::from_parts(http_client()?, shop, api_version, token))
    }

    /// Make a client on a shared HTTP pool.
    pub(crate) fn from_parts(
        http: reqwest::Client,
        shop: ShopDomain,
        api_version: ApiVersion,
        token: String,
    ) -> Self {
        let base_url = format!("https://{shop}");
        Self {
            http,
            shop,
            base_url,
            api_version,
            token,
            retry: RetryPolicy::default(),
        }
    }

    /// Send requests to `base_url` instead of `https://{shop}`. Use it for
    /// a local stub in tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        base_url
            .into()
            .trim_end_matches('/')
            .clone_into(&mut self.base_url);
        self
    }

    /// Set the retry policy.
    #[must_use]
    pub const fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// The shop this client calls.
    #[must_use]
    pub const fn shop(&self) -> &ShopDomain {
        &self.shop
    }

    /// The API version this client uses.
    #[must_use]
    pub const fn api_version(&self) -> &ApiVersion {
        &self.api_version
    }

    /// The GraphQL endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!(
            "{}/admin/api/{}/graphql.json",
            self.base_url, self.api_version
        )
    }

    /// Run a GraphQL document and return its `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] on a transport failure,
    /// [`Error::ShopifyApi`] on a non-success status, [`Error::GraphQl`]
    /// when the response has errors, and [`Error::Throttled`] when the
    /// retries run out.
    pub async fn graphql(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let payload = serde_json::json!({ "query": query, "variables": variables });
        let mut retries = 0;
        loop {
            let response = self
                .http
                .post(self.endpoint())
                .header(ACCESS_TOKEN_HEADER, &self.token)
                .json(&payload)
                .send()
                .await
                .map_err(Error::Http)?;
            let wait = if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                retry_after(response.headers())
            } else if response.status().is_success() {
                let body: serde_json::Value = read_json(response).await?;
                match throttle_wait(&body) {
                    Some(wait) => wait,
                    None => return into_data(body),
                }
            } else {
                return Err(api_error(response).await);
            };
            if retries >= self.retry.max_retries {
                return Err(Error::Throttled { retries });
            }
            retries += 1;
            tracing::debug!(shop = %self.shop, retries, "shopify throttled the call; retrying");
            tokio::time::sleep(wait.min(self.retry.max_wait)).await;
        }
    }

    /// Run a GraphQL document and deserialize its `data` into `T`.
    ///
    /// # Errors
    ///
    /// See [`graphql`](Self::graphql). Also returns [`Error::ShopifyApi`]
    /// when `data` does not match `T`.
    pub async fn query<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<T> {
        let data = self.graphql(query, variables).await?;
        serde_json::from_value(data)
            .map_err(|err| unexpected(&format!("data does not match: {err}")))
    }

    /// Read the shop name and domain. The health check uses it.
    ///
    /// # Errors
    ///
    /// See [`query`](Self::query).
    pub async fn shop_info(&self) -> Result<ShopInfo> {
        #[derive(Deserialize)]
        struct Data {
            shop: ShopInfo,
        }
        let data: Data = self
            .query(
                "query AutumnShopInfo { shop { name myshopifyDomain } }",
                serde_json::json!({}),
            )
            .await?;
        Ok(data.shop)
    }

    /// Subscribe `callback_url` to `topic` (for example `orders/create`)
    /// with `webhookSubscriptionCreate`. Returns the subscription id.
    ///
    /// The compliance topics are not in the GraphQL topic enum. Declare
    /// them in `shopify.app.toml` (`compliance_topics`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] for a malformed topic and
    /// [`Error::Config`] for a compliance topic. See also
    /// [`query`](Self::query). Returns [`Error::GraphQl`] with the
    /// `userErrors` messages when Shopify refuses the subscription.
    pub async fn subscribe_webhook(&self, topic: &str, callback_url: &str) -> Result<String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            webhook_subscription_create: Payload,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Payload {
            webhook_subscription: Option<Subscription>,
            #[serde(default)]
            user_errors: Vec<UserError>,
        }
        #[derive(Deserialize)]
        struct Subscription {
            id: String,
        }
        #[derive(Deserialize)]
        struct UserError {
            message: String,
        }
        let topic = Topic::parse(topic)?;
        if topic.is_compliance() {
            return Err(Error::Config(format!(
                "{topic} is a compliance topic; declare it in shopify.app.toml compliance_topics"
            )));
        }
        let data: Data = self
            .query(
                SUBSCRIBE_MUTATION,
                serde_json::json!({
                    "topic": topic.graphql_enum(),
                    "webhookSubscription": { "uri": callback_url },
                }),
            )
            .await?;
        let payload = data.webhook_subscription_create;
        if !payload.user_errors.is_empty() {
            return Err(Error::GraphQl(
                payload.user_errors.into_iter().map(|e| e.message).collect(),
            ));
        }
        payload
            .webhook_subscription
            .map(|subscription| subscription.id)
            .ok_or_else(|| unexpected("webhookSubscriptionCreate returned no subscription"))
    }
}

/// Build the shared HTTP client: timeout and user agent.
///
/// # Errors
///
/// Returns [`Error::Http`] when the client does not build.
pub(crate) fn http_client() -> Result<reqwest::Client> {
    // No redirects: a redirect would carry the access token or the client
    // secret to another host.
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("autumn-plugin-shopify/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(Error::Http)
}

/// Turn a non-success response into [`Error::ShopifyApi`] with a
/// truncated body.
pub(crate) async fn api_error(response: reqwest::Response) -> Error {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    Error::ShopifyApi {
        status,
        body: body.chars().take(MAX_ERROR_BODY_CHARS).collect(),
    }
}

/// Read a success body as JSON.
async fn read_json(response: reqwest::Response) -> Result<serde_json::Value> {
    let bytes = response.bytes().await.map_err(Error::Http)?;
    serde_json::from_slice(&bytes).map_err(|_| unexpected("the response is not JSON"))
}

/// Return `data`, or the `errors` messages.
fn into_data(mut body: serde_json::Value) -> Result<serde_json::Value> {
    if let Some(errors) = body.get("errors").and_then(serde_json::Value::as_array)
        && !errors.is_empty()
    {
        let messages = errors
            .iter()
            .map(|error| {
                error
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown error")
                    .to_owned()
            })
            .collect();
        return Err(Error::GraphQl(messages));
    }
    match body.get_mut("data").map(serde_json::Value::take) {
        Some(data) if !data.is_null() => Ok(data),
        _ => Err(unexpected("the response has no data")),
    }
}

/// An [`Error::UnexpectedResponse`] for a 200 answer of the wrong shape.
fn unexpected(detail: &str) -> Error {
    Error::UnexpectedResponse(detail.chars().take(MAX_ERROR_BODY_CHARS).collect())
}

/// The wait a `THROTTLED` response asks for, from `extensions.cost`.
///
/// Wait = (requested cost - available points) / restore rate, at least
/// [`MIN_THROTTLE_WAIT`]. One second when the cost data is missing.
/// `None` when the response is not throttled.
pub(crate) fn throttle_wait(body: &serde_json::Value) -> Option<Duration> {
    let throttled = body.get("errors")?.as_array()?.iter().any(|error| {
        error
            .pointer("/extensions/code")
            .and_then(serde_json::Value::as_str)
            == Some("THROTTLED")
    });
    if !throttled {
        return None;
    }
    let cost = body.pointer("/extensions/cost");
    let number = |path: &str| {
        cost.and_then(|c| c.pointer(path))
            .and_then(serde_json::Value::as_f64)
    };
    let wait = match (
        number("/requestedQueryCost"),
        number("/throttleStatus/currentlyAvailable"),
        number("/throttleStatus/restoreRate"),
    ) {
        (Some(requested), Some(available), Some(rate)) if rate > 0.0 => {
            Duration::try_from_secs_f64(((requested - available) / rate).max(0.0))
                .unwrap_or(DEFAULT_WAIT)
                .max(MIN_THROTTLE_WAIT)
        }
        _ => DEFAULT_WAIT,
    };
    Some(wait)
}

/// The wait an HTTP 429 asks for, from `Retry-After` (seconds).
/// One second when the header is missing or bad.
pub(crate) fn retry_after(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<f64>().ok())
        .and_then(|secs| Duration::try_from_secs_f64(secs).ok())
        .unwrap_or(DEFAULT_WAIT)
}

/// The wait when Shopify gives no hint. Shopify recommends one second.
const DEFAULT_WAIT: Duration = Duration::from_secs(1);
/// The shortest wait after a throttle.
const MIN_THROTTLE_WAIT: Duration = Duration::from_millis(100);

/// The `webhookSubscriptionCreate` mutation.
const SUBSCRIBE_MUTATION: &str = "mutation AutumnSubscribeWebhook($topic: WebhookSubscriptionTopic!, $webhookSubscription: WebhookSubscriptionInput!) { webhookSubscriptionCreate(topic: $topic, webhookSubscription: $webhookSubscription) { webhookSubscription { id } userErrors { field message } } }";

#[cfg(test)]
mod tests;
