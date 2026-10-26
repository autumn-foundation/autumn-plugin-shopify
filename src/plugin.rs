//! The Autumn plugin: [`ShopifyPlugin`], [`ShopifyRuntime`], and the
//! [`Shopify`] extractor.
//!
//! ```ignore
//! use autumn_plugin_shopify::{ShopifyPlugin, WebhookContext};
//! use autumn_web::prelude::*;
//!
//! async fn order_created(ctx: WebhookContext) -> AutumnResult<()> {
//!     tracing::info!(shop = %ctx.shop, "order created");
//!     Ok(())
//! }
//!
//! #[autumn_web::main]
//! async fn main() {
//!     autumn_web::app()
//!         .plugin(ShopifyPlugin::new().webhook("orders/create", order_created))
//!         .run()
//!         .await;
//! }
//! ```
//!
//! The plugin declares the `[shopify]` section, mounts its routes under
//! `/shopify`, and installs an `on_startup` hook. The hook loads and checks
//! the config, builds the [`ShopifyRuntime`], and puts it in the
//! [`AppState`] extensions. A bad config stops the boot.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use autumn_web::AppState;
use autumn_web::AutumnError;
use autumn_web::actuator::IndicatorGroup;
use autumn_web::app::AppBuilder;
use autumn_web::plugin::Plugin;
use autumn_web::plugin_contract::PluginContract;
use autumn_web::reexports::axum::Router;
use autumn_web::reexports::axum::extract::FromRequestParts;
use autumn_web::reexports::http::request::Parts;
use autumn_web::route_listing::RouteInfo;

use crate::client::{RetryPolicy, ShopifyClient};
use crate::config::ShopifyConfig;
use crate::delivery::{DeliveryStore, InMemoryDeliveryStore};
use crate::error::{Error, Result};
use crate::tokens::{InMemoryTokenStore, TokenStore};
use crate::types::{ApiVersion, ShopDomain};
use crate::verify::SecretSet;
use crate::webhooks::{IntoWebhookHandler, WebhookHandler, WebhookRegistry};

/// The `autumn-web` range this plugin supports. Keep it equal to the
/// `autumn-web` requirement in `Cargo.toml`.
const SUPPORTED_AUTUMN_WEB: &str = "0.8";

/// A token refreshes when it expires within this many seconds.
pub const REFRESH_MARGIN_SECS: i64 = 60;

/// A builder closure for [`ShopifyPlugin::configure`].
type ConfigureFn = Arc<dyn Fn(&mut ShopifyConfig) + Send + Sync + 'static>;

/// Runtime state shared by the routes and the [`Shopify`] extractor.
///
/// The startup hook puts it in the [`AppState`] extensions.
pub struct ShopifyRuntime {
    config: ShopifyConfig,
    secrets: SecretSet,
    api_version: ApiVersion,
    single_store: Option<(ShopDomain, String)>,
    http: reqwest::Client,
    admin_base_url: Option<String>,
    retry: RetryPolicy,
    registry: WebhookRegistry,
    tokens: Arc<dyn TokenStore>,
    deliveries: Arc<dyn DeliveryStore>,
    refresh_locks: Mutex<HashMap<ShopDomain, Arc<tokio::sync::Mutex<()>>>>,
}

/// `Debug` shows no secrets and no tokens.
impl std::fmt::Debug for ShopifyRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopifyRuntime")
            .field("config", &self.config)
            .field(
                "single_store",
                &self.single_store.as_ref().map(|(shop, _)| shop),
            )
            .field("topics", &self.registry.topics())
            .finish_non_exhaustive()
    }
}

impl ShopifyRuntime {
    /// The resolved, validated config.
    #[must_use]
    pub const fn config(&self) -> &ShopifyConfig {
        &self.config
    }

    /// The client secrets.
    #[must_use]
    pub const fn secrets(&self) -> &SecretSet {
        &self.secrets
    }

    /// The webhook handlers.
    #[must_use]
    pub const fn registry(&self) -> &WebhookRegistry {
        &self.registry
    }

    /// The token store.
    #[must_use]
    pub const fn token_store(&self) -> &Arc<dyn TokenStore> {
        &self.tokens
    }

    /// The duplicate-delivery store.
    #[must_use]
    pub const fn delivery_store(&self) -> &Arc<dyn DeliveryStore> {
        &self.deliveries
    }

    /// The shared HTTP pool.
    pub(crate) const fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// The origin for Admin API and OAuth calls to `shop`.
    pub(crate) fn admin_origin(&self, shop: &ShopDomain) -> String {
        self.admin_base_url.as_deref().map_or_else(
            || format!("https://{shop}"),
            |base| base.trim_end_matches('/').to_owned(),
        )
    }

    /// The client for the single-store shop.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when `shop` or `SHOPIFY_ACCESS_TOKEN` is
    /// not set.
    pub fn client(&self) -> Result<ShopifyClient> {
        let (shop, token) = self.single_store.as_ref().ok_or_else(|| {
            Error::Config(format!(
                "no single-store client: set [shopify] shop and {}",
                crate::config::ACCESS_TOKEN_ENV
            ))
        })?;
        Ok(self.make_client(shop, token.clone()))
    }

    /// A client on the shared pool, with the configured version and retry.
    fn make_client(&self, shop: &ShopDomain, token: String) -> ShopifyClient {
        ShopifyClient::from_parts(
            self.http.clone(),
            shop.clone(),
            self.api_version.clone(),
            token,
        )
        .with_base_url(self.admin_origin(shop))
        .with_retry(self.retry)
    }

    /// The refresh lock for `shop`.
    fn refresh_lock(&self, shop: &ShopDomain) -> Result<Arc<tokio::sync::Mutex<()>>> {
        let mut locks = self
            .refresh_locks
            .lock()
            .map_err(|_| Error::Store("refresh lock table is poisoned".to_owned()))?;
        Ok(Arc::clone(locks.entry(shop.clone()).or_default()))
    }

    /// The client for `shop`, at Unix time `now`.
    ///
    /// The single-store shop uses the fixed token. Other shops use the
    /// token store. A token that expires within [`REFRESH_MARGIN_SECS`]
    /// refreshes first; one refresh per shop runs at a time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInstalled`] when the shop has no token,
    /// [`Error::Reauthorize`] when the token cannot refresh, or a store or
    /// HTTP error.
    pub async fn client_for(&self, shop: &ShopDomain, now: i64) -> Result<ShopifyClient> {
        if let Some((single, token)) = &self.single_store
            && single == shop
        {
            return Ok(self.make_client(shop, token.clone()));
        }
        let token = self
            .tokens
            .get(shop)
            .await?
            .ok_or_else(|| Error::NotInstalled(shop.to_string()))?;
        if !token.needs_refresh(now, REFRESH_MARGIN_SECS) {
            return Ok(self.make_client(shop, token.access_token));
        }

        // One refresh per shop at a time. Shopify retires the old refresh
        // token, so a second refresh with it would fail.
        let lock = self.refresh_lock(shop)?;
        let _guard = lock.lock().await;
        let token = self
            .tokens
            .get(shop)
            .await?
            .ok_or_else(|| Error::NotInstalled(shop.to_string()))?;
        if !token.needs_refresh(now, REFRESH_MARGIN_SECS) {
            return Ok(self.make_client(shop, token.access_token));
        }
        let refresh = match token.refresh_token.as_deref() {
            Some(refresh) if token.can_refresh(now) => refresh,
            _ => {
                self.tokens.delete(shop).await?;
                return Err(Error::Reauthorize(shop.to_string()));
            }
        };
        match crate::oauth::refresh_token(self, shop, refresh, now).await {
            Ok(fresh) => {
                let access = fresh.access_token.clone();
                self.tokens.put(shop, fresh).await?;
                tracing::info!(shop = %shop, "shopify token refreshed");
                Ok(self.make_client(shop, access))
            }
            Err(Error::Reauthorize(_)) => {
                self.tokens.delete(shop).await?;
                tracing::warn!(shop = %shop, "shopify refresh refused; the shop must install again");
                Err(Error::Reauthorize(shop.to_string()))
            }
            Err(err) => Err(err),
        }
    }
}

/// The plugin handle for app routes.
///
/// ```ignore
/// #[get("/products")]
/// async fn products(shopify: Shopify) -> AutumnResult<String> {
///     let client = shopify.client().map_err(|e| e.to_autumn_error())?;
///     // ...
/// }
/// ```
///
/// Extraction fails with 503 when the plugin is not installed.
#[derive(Clone)]
pub struct Shopify {
    runtime: Arc<ShopifyRuntime>,
    state: AppState,
}

impl std::fmt::Debug for Shopify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shopify")
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl Shopify {
    /// Read the handle from the app state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingRuntime`] when the plugin is not installed.
    pub fn from_state(state: &AppState) -> Result<Self> {
        let runtime = state
            .extension::<ShopifyRuntime>()
            .ok_or(Error::MissingRuntime)?;
        Ok(Self::from_runtime(runtime, state.clone()))
    }

    /// Make a handle from a runtime and a state.
    pub(crate) const fn from_runtime(runtime: Arc<ShopifyRuntime>, state: AppState) -> Self {
        Self { runtime, state }
    }

    /// The runtime.
    #[must_use]
    pub const fn runtime(&self) -> &Arc<ShopifyRuntime> {
        &self.runtime
    }

    /// The client for the single-store shop.
    ///
    /// # Errors
    ///
    /// See [`ShopifyRuntime::client`].
    pub fn client(&self) -> Result<ShopifyClient> {
        self.runtime.client()
    }

    /// The client for `shop`. Time comes from the app clock.
    ///
    /// # Errors
    ///
    /// See [`ShopifyRuntime::client_for`].
    pub async fn client_for(&self, shop: &ShopDomain) -> Result<ShopifyClient> {
        let now = self.state.clock().now().timestamp();
        self.runtime.client_for(shop, now).await
    }
}

impl FromRequestParts<AppState> for Shopify {
    type Rejection = AutumnError;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &AppState,
    ) -> std::result::Result<Self, Self::Rejection> {
        Self::from_state(state).map_err(|err| err.to_autumn_error())
    }
}

/// Shopify as an Autumn plugin.
#[derive(Clone, Default)]
pub struct ShopifyPlugin {
    configure: Vec<ConfigureFn>,
    webhooks: Vec<(String, WebhookHandler)>,
    token_store: Option<Arc<dyn TokenStore>>,
    delivery_store: Option<Arc<dyn DeliveryStore>>,
    admin_base_url: Option<String>,
}

impl std::fmt::Debug for ShopifyPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let topics: Vec<&str> = self.webhooks.iter().map(|(t, _)| t.as_str()).collect();
        f.debug_struct("ShopifyPlugin")
            .field("topics", &topics)
            .finish_non_exhaustive()
    }
}

impl ShopifyPlugin {
    /// Make the plugin.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Change config values in code. The closure runs after the file and
    /// the environment, so its values win. It cannot set secrets.
    #[must_use]
    pub fn configure(
        mut self,
        configure: impl Fn(&mut ShopifyConfig) + Send + Sync + 'static,
    ) -> Self {
        self.configure.push(Arc::new(configure));
        self
    }

    /// Handle webhooks for `topic`, for example `orders/create`.
    ///
    /// A malformed or repeated topic stops the boot.
    #[must_use]
    pub fn webhook(mut self, topic: impl Into<String>, handler: impl IntoWebhookHandler) -> Self {
        self.webhooks.push((topic.into(), handler.into_handler()));
        self
    }

    /// Replace the in-memory token store.
    #[must_use]
    pub fn token_store(mut self, store: Arc<dyn TokenStore>) -> Self {
        self.token_store = Some(store);
        self
    }

    /// Replace the in-memory duplicate-delivery store.
    #[must_use]
    pub fn delivery_store(mut self, store: Arc<dyn DeliveryStore>) -> Self {
        self.delivery_store = Some(store);
        self
    }

    /// Send Admin API and OAuth calls to `base_url` instead of
    /// `https://{shop}`. Use it for a local stub in tests.
    #[must_use]
    pub fn admin_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.admin_base_url = Some(base_url.into());
        self
    }

    /// Build the runtime from a loaded config: apply the builder closures,
    /// validate, and register the webhook handlers.
    ///
    /// The startup hook calls this with [`ShopifyConfig::load`]. Tests call
    /// it with [`ShopifyConfig::from_sources`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the config is not valid or a webhook
    /// topic is malformed or repeated.
    pub fn build_runtime(&self, config: ShopifyConfig) -> Result<ShopifyRuntime> {
        let mut config = config;
        for configure in &self.configure {
            configure(&mut config);
        }
        config.validate()?;
        let secrets = config.secrets()?;
        let api_version = config.api_version()?;
        let single_store = match (config.shop_domain()?, config.access_token()) {
            (Some(shop), Some(token)) => Some((shop, token.to_owned())),
            _ => None,
        };
        let mut registry = WebhookRegistry::new();
        for (topic, handler) in &self.webhooks {
            registry.register(topic, Arc::clone(handler))?;
        }
        let retry = RetryPolicy {
            max_retries: config.max_throttle_retries,
            ..RetryPolicy::default()
        };
        Ok(ShopifyRuntime {
            secrets,
            api_version,
            single_store,
            http: crate::client::http_client()?,
            admin_base_url: self.admin_base_url.clone(),
            retry,
            registry,
            tokens: self
                .token_store
                .clone()
                .unwrap_or_else(|| Arc::new(InMemoryTokenStore::new())),
            deliveries: self
                .delivery_store
                .clone()
                .unwrap_or_else(|| Arc::new(InMemoryDeliveryStore::default())),
            refresh_locks: Mutex::new(HashMap::new()),
            config,
        })
    }
}

impl ShopifyPlugin {
    /// The startup work: build the runtime, log warnings, register the
    /// health indicator, and put the runtime in the app state.
    fn start(&self, state: &AppState, config: ShopifyConfig) -> Result<()> {
        let runtime = self.build_runtime(config)?;
        for warning in startup_warnings(&runtime, &state.config_arc()) {
            tracing::warn!("{warning}");
        }
        if let Ok(client) = runtime.client() {
            // A duplicate name means the plugin is installed twice; the
            // framework warns about that already.
            let _ = state.health_indicator_registry().register(
                "shopify",
                IndicatorGroup::Readiness,
                crate::health::indicator(&client),
            );
        }
        tracing::info!(
            topics = runtime.registry().topics().len(),
            oauth = runtime.config().oauth_enabled(),
            single_store = runtime.single_store.is_some(),
            "shopify plugin ready"
        );
        state.extension_or_insert_with(|| runtime);
        Ok(())
    }
}

impl Plugin for ShopifyPlugin {
    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("autumn-plugin-shopify")
    }

    /// Declare the supported `autumn-web` range. A mismatch fails at
    /// registration with both versions named.
    fn contract(&self) -> Option<PluginContract> {
        Some(
            PluginContract::new(env!("CARGO_PKG_NAME"))
                .plugin_version(env!("CARGO_PKG_VERSION"))
                .autumn_web(SUPPORTED_AUTUMN_WEB),
        )
    }

    fn build(self, app: AppBuilder) -> AppBuilder {
        let (router, infos) = mount();
        app.config_section(crate::config::CONFIG_SECTION)
            .on_startup(move |state: AppState| {
                let plugin = self.clone();
                async move {
                    let config = ShopifyConfig::load().map_err(|err| err.to_autumn_error())?;
                    plugin
                        .start(&state, config)
                        .map_err(|err| err.to_autumn_error())
                }
            })
            .nest("/shopify", router)
            .declare_plugin_routes(infos)
    }
}

/// Startup warnings: compliance topics with no handler (OAuth on), and a
/// webhook path that CSRF checks would block.
pub(crate) fn startup_warnings(
    runtime: &ShopifyRuntime,
    app_config: &autumn_web::config::AutumnConfig,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if runtime.config().oauth_enabled() {
        for topic in crate::types::Topic::COMPLIANCE {
            if !runtime.registry().contains(topic) {
                warnings.push(format!(
                    "shopify: no handler for the mandatory compliance topic {topic}; \
                     public apps must handle it"
                ));
            }
        }
    }
    let csrf = &app_config.security.csrf;
    if csrf.enabled
        && !csrf
            .exempt_paths
            .iter()
            .any(|path| covers(path, WEBHOOK_PATH))
    {
        warnings.push(format!(
            "shopify: CSRF checks block {WEBHOOK_PATH}; add it to security.csrf.exempt_paths"
        ));
    }
    warnings
}

/// The plugin routes under `/shopify`, with their route metadata.
///
/// [`AppBuilder::declare_plugin_routes`] gets the metadata, so
/// `autumn routes audit` sees the mount as enumerable.
pub(crate) fn mount() -> (Router<AppState>, Vec<RouteInfo>) {
    let mut router = Router::<AppState>::new();
    let mut infos = Vec::new();
    let all_routes = crate::webhooks::webhook_routes()
        .into_iter()
        .chain(crate::oauth::oauth_routes());
    for route in all_routes {
        infos.push(RouteInfo {
            method: route.method.to_string(),
            path: format!("/shopify{}", route.path),
            handler: route.name.to_owned(),
            module: Some(module_path!().to_owned()),
            ..Default::default()
        });
        router = router.route(route.path, route.handler);
    }
    (router, infos)
}

/// The webhook route path.
const WEBHOOK_PATH: &str = "/shopify/webhooks";

/// True when the exempt prefix `prefix` covers `path`, with the same
/// segment rule as Autumn's CSRF layer.
fn covers(prefix: &str, path: &str) -> bool {
    path == prefix
        || (path.starts_with(prefix)
            && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')))
}

#[cfg(test)]
mod tests;
