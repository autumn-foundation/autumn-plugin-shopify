//! Error types for the Shopify plugin.
//!
//! [`Error`] is the plugin error. [`ErrorKind`] classifies it.
//! [`Error::to_autumn_error`] maps each kind to an HTTP status.
//!
//! Do not use `?` to change an [`Error`] into an [`AutumnError`]. Autumn has
//! a blanket `From` impl that gives 500 for every error. Call
//! [`Error::to_autumn_error`].

use autumn_web::AutumnError;
use autumn_web::reexports::http::StatusCode;
use thiserror::Error;

/// Classifies an [`Error`] without its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The `[shopify]` config is missing or not valid.
    Config,
    /// An HMAC is missing, malformed, or wrong.
    Signature,
    /// The request is malformed (headers, query, or shop domain).
    InvalidRequest,
    /// The request body is larger than the limit.
    PayloadTooLarge,
    /// A JSON payload does not parse.
    Json,
    /// A Shopify call failed at the transport level.
    Http,
    /// Shopify answered with a non-success status.
    ShopifyApi,
    /// The GraphQL response has errors.
    GraphQl,
    /// Shopify throttled the call and the retries ran out.
    Throttled,
    /// Shopify answered 200, but the body has the wrong shape.
    UnexpectedResponse,
    /// Another delivery of this webhook id still runs.
    InProgress,
    /// The OAuth state does not match the browser cookie.
    StateMismatch,
    /// The merchant did not grant all requested scopes.
    ScopeMismatch,
    /// The shop has no stored access token.
    NotInstalled,
    /// The token cannot refresh. The merchant must install the app again.
    Reauthorize,
    /// OAuth is off (`[shopify] app_url` is not set).
    OAuthDisabled,
    /// A token or delivery store failed.
    Store,
    /// The app does not use the plugin (no runtime in the app state).
    MissingRuntime,
}

/// The plugin error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The `[shopify]` config is missing or not valid.
    #[error("shopify config error: {0}")]
    Config(String),

    /// An HMAC is missing, malformed, or wrong.
    #[error("shopify signature error: {0}")]
    Signature(String),

    /// The request is malformed.
    #[error("shopify invalid request: {0}")]
    InvalidRequest(String),

    /// The request body is larger than the limit.
    #[error("shopify request body is larger than {limit} bytes")]
    PayloadTooLarge {
        /// The limit in bytes.
        limit: usize,
    },

    /// A JSON payload does not parse.
    #[error("shopify json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A Shopify call failed at the transport level.
    #[error("shopify http error: {0}")]
    Http(#[from] reqwest::Error),

    /// Shopify answered with a non-success status.
    #[error("shopify api error: status {status}: {body}")]
    ShopifyApi {
        /// The HTTP status from Shopify.
        status: u16,
        /// The response body, truncated to 500 chars.
        body: String,
    },

    /// The GraphQL response has errors.
    #[error("shopify graphql error: {}", .0.join("; "))]
    GraphQl(Vec<String>),

    /// Shopify throttled the call and the retries ran out.
    #[error("shopify throttled the request after {retries} retries")]
    Throttled {
        /// The number of retries done.
        retries: u32,
    },

    /// Shopify answered 200, but the body has the wrong shape.
    #[error("shopify response has the wrong shape: {0}")]
    UnexpectedResponse(String),

    /// Another delivery of this webhook id still runs.
    #[error("shopify webhook {0} is in progress")]
    InProgress(String),

    /// The OAuth state does not match the browser cookie.
    #[error("shopify oauth state does not match")]
    StateMismatch,

    /// The merchant did not grant all requested scopes.
    #[error("shopify scopes not granted: {}", .missing.join(","))]
    ScopeMismatch {
        /// The requested scopes that are missing.
        missing: Vec<String>,
    },

    /// The shop has no stored access token.
    #[error("shop {0} has no stored token; install the app")]
    NotInstalled(String),

    /// The token cannot refresh. The merchant must install the app again.
    #[error("shop {0} must install the app again")]
    Reauthorize(String),

    /// OAuth is off.
    #[error("shopify oauth is off; set [shopify] app_url")]
    OAuthDisabled,

    /// A token or delivery store failed.
    #[error("shopify store error: {0}")]
    Store(String),

    /// The app does not use the plugin (no runtime in the app state).
    #[error("shopify runtime is missing; add ShopifyPlugin to the app")]
    MissingRuntime,
}

impl Error {
    /// Classify this error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::Config(_) => ErrorKind::Config,
            Self::Signature(_) => ErrorKind::Signature,
            Self::InvalidRequest(_) => ErrorKind::InvalidRequest,
            Self::PayloadTooLarge { .. } => ErrorKind::PayloadTooLarge,
            Self::Json(_) => ErrorKind::Json,
            Self::Http(_) => ErrorKind::Http,
            Self::ShopifyApi { .. } => ErrorKind::ShopifyApi,
            Self::GraphQl(_) => ErrorKind::GraphQl,
            Self::Throttled { .. } => ErrorKind::Throttled,
            Self::UnexpectedResponse(_) => ErrorKind::UnexpectedResponse,
            Self::InProgress(_) => ErrorKind::InProgress,
            Self::StateMismatch => ErrorKind::StateMismatch,
            Self::ScopeMismatch { .. } => ErrorKind::ScopeMismatch,
            Self::NotInstalled(_) => ErrorKind::NotInstalled,
            Self::Reauthorize(_) => ErrorKind::Reauthorize,
            Self::OAuthDisabled => ErrorKind::OAuthDisabled,
            Self::Store(_) => ErrorKind::Store,
            Self::MissingRuntime => ErrorKind::MissingRuntime,
        }
    }

    /// The HTTP status this error maps to.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self.kind() {
            ErrorKind::Signature | ErrorKind::NotInstalled | ErrorKind::Reauthorize => {
                StatusCode::UNAUTHORIZED
            }
            ErrorKind::InvalidRequest | ErrorKind::Json => StatusCode::BAD_REQUEST,
            ErrorKind::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorKind::StateMismatch | ErrorKind::ScopeMismatch => StatusCode::FORBIDDEN,
            ErrorKind::OAuthDisabled => StatusCode::NOT_FOUND,
            ErrorKind::InProgress => StatusCode::CONFLICT,
            ErrorKind::Http
            | ErrorKind::ShopifyApi
            | ErrorKind::GraphQl
            | ErrorKind::UnexpectedResponse => StatusCode::BAD_GATEWAY,
            ErrorKind::Throttled | ErrorKind::MissingRuntime => StatusCode::SERVICE_UNAVAILABLE,
            ErrorKind::Config | ErrorKind::Store => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Convert into an [`AutumnError`] with the status from
    /// [`status`](Self::status).
    #[must_use]
    pub fn to_autumn_error(&self) -> AutumnError {
        AutumnError::internal_server_error_msg(self.to_string()).with_status(self.status())
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
