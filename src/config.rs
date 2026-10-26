//! Layered configuration for the Shopify plugin.
//!
//! [`ShopifyConfig`] reads the `[shopify]` section of `autumn.toml`, then
//! the `SHOPIFY_*` environment variables, then the builder closures from
//! [`ShopifyPlugin::configure`](crate::plugin::ShopifyPlugin::configure).
//! A later layer wins.
//!
//! Secrets come only from the environment:
//!
//! | Variable | Holds |
//! |---|---|
//! | `SHOPIFY_API_SECRET` | The app client secret (required). |
//! | `SHOPIFY_API_SECRET_PREVIOUS` | The old client secret during rotation. |
//! | `SHOPIFY_ACCESS_TOKEN` | A fixed Admin API token (single-store apps). |
//!
//! A secret key in `[shopify]` stops config loading.
//!
//! ```toml
//! [shopify]
//! api_key = "client id from the Dev Dashboard"
//! shop = "my-store.myshopify.com"      # single-store apps
//! api_version = "2026-10"
//! app_url = "https://app.example.com"  # turns OAuth on
//! scopes = ["read_orders", "write_products"]
//! after_install_path = "/"
//! max_throttle_retries = 3
//! ```

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::types::{ApiVersion, DEFAULT_API_VERSION, ShopDomain};
use crate::verify::SecretSet;

/// Name of the `autumn.toml` section this plugin reads.
pub const CONFIG_SECTION: &str = "shopify";
/// Environment variable for the app client secret.
pub const API_SECRET_ENV: &str = "SHOPIFY_API_SECRET";
/// Environment variable for the previous client secret.
pub const PREVIOUS_API_SECRET_ENV: &str = "SHOPIFY_API_SECRET_PREVIOUS";
/// Environment variable for a fixed Admin API access token.
pub const ACCESS_TOKEN_ENV: &str = "SHOPIFY_ACCESS_TOKEN";

/// Keys that must never appear in `[shopify]`.
const SECRET_KEYS: [&str; 6] = [
    "api_secret",
    "client_secret",
    "access_token",
    "secret",
    "token",
    "api_secret_previous",
];

/// Configuration for the Shopify plugin.
///
/// `Debug` redacts the secrets. App code cannot read them:
///
/// ```compile_fail
/// let config = autumn_plugin_shopify::ShopifyConfig::default();
/// let _ = config.secrets();
/// ```
///
/// ```compile_fail
/// let config = autumn_plugin_shopify::ShopifyConfig::default();
/// let _ = config.access_token();
/// ```
#[derive(Clone)]
pub struct ShopifyConfig {
    /// The app client id (`api_key`). OAuth needs it.
    pub api_key: Option<String>,
    /// The shop of a single-store app, for example `my-store.myshopify.com`.
    pub shop: Option<String>,
    /// The Admin API version.
    pub api_version: String,
    /// The access scopes OAuth asks for.
    pub scopes: Vec<String>,
    /// The public base URL of the app. Setting it turns OAuth on.
    pub app_url: Option<String>,
    /// The local path the browser goes to after an install.
    pub after_install_path: String,
    /// How many times a throttled Admin API call retries.
    pub max_throttle_retries: u32,
    api_secret: Option<String>,
    previous_api_secret: Option<String>,
    access_token: Option<String>,
}

impl std::fmt::Debug for ShopifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        f.debug_struct("ShopifyConfig")
            .field("api_key", &self.api_key)
            .field("shop", &self.shop)
            .field("api_version", &self.api_version)
            .field("scopes", &self.scopes)
            .field("app_url", &self.app_url)
            .field("after_install_path", &self.after_install_path)
            .field("max_throttle_retries", &self.max_throttle_retries)
            .field("api_secret", &redact(&self.api_secret))
            .field("previous_api_secret", &redact(&self.previous_api_secret))
            .field("access_token", &redact(&self.access_token))
            .finish()
    }
}

impl Default for ShopifyConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            shop: None,
            api_version: DEFAULT_API_VERSION.to_owned(),
            scopes: Vec::new(),
            app_url: None,
            after_install_path: "/".to_owned(),
            max_throttle_retries: 3,
            api_secret: None,
            previous_api_secret: None,
            access_token: None,
        }
    }
}

/// The raw `[shopify]` table. Every field is optional.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    api_key: Option<String>,
    shop: Option<String>,
    api_version: Option<String>,
    scopes: Option<Scopes>,
    app_url: Option<String>,
    after_install_path: Option<String>,
    max_throttle_retries: Option<u32>,
}

/// Scopes as a TOML array or as one comma-separated string.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Scopes {
    List(Vec<String>),
    Csv(String),
}

impl ShopifyConfig {
    /// Read `autumn.toml` and the process environment. Does not validate.
    ///
    /// The loader reads the file from `AUTUMN_MANIFEST_DIR` first, then from
    /// the current directory. A missing file or section is not an error.
    /// The loader reads only `autumn.toml`: it does not apply Autumn profile
    /// layering. Use the `SHOPIFY_*` variables for values that change per
    /// profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the file is not valid TOML, the
    /// section has a secret or an unknown key, or an env value is bad.
    pub fn load() -> Result<Self> {
        let path = config_file_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => Some(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(Error::Config(format!(
                    "cannot read {}: {err}",
                    path.display()
                )));
            }
        };
        Self::from_sources(text.as_deref(), |name| std::env::var(name).ok())
    }

    /// Build the config from a TOML document and an environment lookup.
    /// Does not validate.
    ///
    /// Use it in tests. Pass a closure, not the process environment.
    ///
    /// # Errors
    ///
    /// See [`load`](Self::load).
    pub fn from_sources(
        toml_text: Option<&str>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let mut config = match toml_text {
            Some(text) => Self::from_toml_str(text)?,
            None => Self::default(),
        };
        config.apply_env_with(env)?;
        Ok(config)
    }

    /// Parse the `[shopify]` table of a TOML document. Does not validate.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the TOML is not valid, the section is
    /// not a table, or it has a secret or an unknown key.
    pub fn from_toml_str(document: &str) -> Result<Self> {
        let table: toml::Table = document
            .parse()
            .map_err(|err| Error::Config(format!("invalid autumn.toml: {err}")))?;
        let Some(section) = table.get(CONFIG_SECTION) else {
            return Ok(Self::default());
        };
        let section = section
            .as_table()
            .ok_or_else(|| Error::Config("[shopify] must be a table".to_owned()))?;
        // Fail closed on secrets before reading any other key. The error
        // names the key, never the value.
        if let Some(key) = section.keys().find(|key| is_secret_key(key)) {
            return Err(Error::Config(format!(
                "[shopify] {key} is not allowed: secrets come only from the \
                 {API_SECRET_ENV}, {PREVIOUS_API_SECRET_ENV}, and {ACCESS_TOKEN_ENV} \
                 environment variables"
            )));
        }
        let raw: RawConfig = section
            .clone()
            .try_into()
            .map_err(|err| Error::Config(format!("invalid [shopify] section: {err}")))?;
        let defaults = Self::default();
        Ok(Self {
            api_key: raw.api_key,
            shop: raw.shop,
            api_version: raw.api_version.unwrap_or(defaults.api_version),
            scopes: match raw.scopes {
                Some(Scopes::List(list)) => list,
                Some(Scopes::Csv(csv)) => split_csv(&csv),
                None => Vec::new(),
            },
            app_url: raw.app_url,
            after_install_path: raw
                .after_install_path
                .unwrap_or(defaults.after_install_path),
            max_throttle_retries: raw
                .max_throttle_retries
                .unwrap_or(defaults.max_throttle_retries),
            api_secret: None,
            previous_api_secret: None,
            access_token: None,
        })
    }

    /// Apply `SHOPIFY_*` variables from `get`.
    ///
    /// Reads `SHOPIFY_API_KEY`, `SHOPIFY_SHOP`, `SHOPIFY_API_VERSION`,
    /// `SHOPIFY_APP_URL`, `SHOPIFY_SCOPES` (comma-separated),
    /// `SHOPIFY_AFTER_INSTALL_PATH`, `SHOPIFY_MAX_THROTTLE_RETRIES`, and the
    /// three secret variables. Blank values count as unset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when `SHOPIFY_MAX_THROTTLE_RETRIES` is not
    /// a number.
    pub fn apply_env_with(&mut self, get: impl Fn(&str) -> Option<String>) -> Result<()> {
        let get = |name: &str| get(name).filter(|value| !value.trim().is_empty());
        if let Some(value) = get("SHOPIFY_AFTER_INSTALL_PATH") {
            self.after_install_path = value;
        }
        if let Some(value) = get("SHOPIFY_MAX_THROTTLE_RETRIES") {
            self.max_throttle_retries = value.trim().parse().map_err(|_| {
                Error::Config("SHOPIFY_MAX_THROTTLE_RETRIES must be a number".to_owned())
            })?;
        }
        if let Some(value) = get("SHOPIFY_API_KEY") {
            self.api_key = Some(value);
        }
        if let Some(value) = get("SHOPIFY_SHOP") {
            self.shop = Some(value);
        }
        if let Some(value) = get("SHOPIFY_API_VERSION") {
            self.api_version = value;
        }
        if let Some(value) = get("SHOPIFY_APP_URL") {
            self.app_url = Some(value);
        }
        if let Some(value) = get("SHOPIFY_SCOPES") {
            self.scopes = split_csv(&value);
        }
        if let Some(value) = get(API_SECRET_ENV) {
            self.api_secret = Some(value);
        }
        if let Some(value) = get(PREVIOUS_API_SECRET_ENV) {
            self.previous_api_secret = Some(value);
        }
        if let Some(value) = get(ACCESS_TOKEN_ENV) {
            self.access_token = Some(value);
        }
        Ok(())
    }

    /// Check that the config is complete and well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for the first problem found.
    pub fn validate(&self) -> Result<()> {
        self.secrets()?;
        self.shop_domain()?;
        self.api_version()?;
        if self.max_throttle_retries > MAX_THROTTLE_RETRIES {
            return Err(Error::Config(format!(
                "max_throttle_retries must be at most {MAX_THROTTLE_RETRIES}"
            )));
        }
        validate_local_path(&self.after_install_path)?;
        if let Some(app_url) = &self.app_url {
            validate_app_url(app_url)?;
            if self
                .api_key
                .as_deref()
                .is_none_or(|key| key.trim().is_empty())
            {
                return Err(Error::Config(
                    "OAuth needs [shopify] api_key (the app client id)".to_owned(),
                ));
            }
            if self.scopes.is_empty() {
                return Err(Error::Config("OAuth needs [shopify] scopes".to_owned()));
            }
            if let Some(scope) = self.scopes.iter().find(|scope| !is_scope(scope)) {
                return Err(Error::Config(format!(
                    "scope {scope:?} must be lowercase letters, digits, and '_'"
                )));
            }
        }
        Ok(())
    }

    /// True when OAuth is on (`app_url` is set).
    #[must_use]
    pub const fn oauth_enabled(&self) -> bool {
        self.app_url.is_some()
    }

    /// The client secrets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when `SHOPIFY_API_SECRET` is not set.
    pub(crate) fn secrets(&self) -> Result<SecretSet> {
        let current = self.api_secret.clone().ok_or_else(|| {
            Error::Config(format!(
                "the client secret is missing; set the {API_SECRET_ENV} environment variable"
            ))
        })?;
        SecretSet::new(current, self.previous_api_secret.clone())
    }

    /// The fixed access token from `SHOPIFY_ACCESS_TOKEN`, if set.
    #[must_use]
    pub(crate) fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    /// The single-store shop, parsed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when `shop` is set but not valid.
    pub fn shop_domain(&self) -> Result<Option<ShopDomain>> {
        self.shop
            .as_deref()
            .map(|shop| {
                ShopDomain::parse(shop.trim()).map_err(|_| {
                    Error::Config(format!(
                        "[shopify] shop {shop:?} must be a *.myshopify.com domain"
                    ))
                })
            })
            .transpose()
    }

    /// The API version, parsed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the version is malformed.
    pub fn api_version(&self) -> Result<ApiVersion> {
        ApiVersion::parse(&self.api_version)
    }

    /// The OAuth redirect URI: `{app_url}/shopify/auth/callback`.
    #[must_use]
    pub fn redirect_uri(&self) -> Option<String> {
        self.app_url.as_deref().map(|url| {
            format!(
                "{}{}",
                url.trim_end_matches('/'),
                crate::oauth::CALLBACK_PATH
            )
        })
    }
}

/// The largest allowed `max_throttle_retries`.
const MAX_THROTTLE_RETRIES: u32 = 10;

/// True for a key that names a secret.
fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    SECRET_KEYS.contains(&key.as_str()) || key.ends_with("_secret") || key.ends_with("_token")
}

/// Split a comma-separated list. Drop the blank items.
fn split_csv(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// True for a well-formed scope, for example `write_products`.
fn is_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Check `app_url`: absolute, `https` (or `http` on a loopback host), no
/// query, no fragment.
fn validate_app_url(app_url: &str) -> Result<()> {
    let url = url::Url::parse(app_url)
        .map_err(|_| Error::Config(format!("app_url {app_url:?} is not a valid URL")))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !scheme_ok {
        return Err(Error::Config(
            "app_url must use https (http only for localhost)".to_owned(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Config(
            "app_url must not have a query or a fragment".to_owned(),
        ));
    }
    Ok(())
}

/// Check `after_install_path`: a local path, never an absolute or
/// scheme-relative URL (no open redirect).
fn validate_local_path(path: &str) -> Result<()> {
    let local = path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.contains('#')
        && !path.chars().any(char::is_control);
    if local {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "after_install_path {path:?} must be a local path such as \"/\""
        )))
    }
}

/// Use the framework's config-file discovery order.
fn config_file_path() -> PathBuf {
    if let Ok(manifest_dir) = std::env::var("AUTUMN_MANIFEST_DIR") {
        let candidate = PathBuf::from(manifest_dir).join("autumn.toml");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("autumn.toml")
}

#[cfg(test)]
mod tests;
