//! The Autumn plugin: [`ShopifyPlugin`], [`ShopifyRuntime`], and the
//! [`Shopify`] extractor.
//!
//! ```no_run
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
//! [`AppState`] extensions. A bad config stops the startup.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use autumn_web::actuator::IndicatorGroup;
use autumn_web::app::AppBuilder;
use autumn_web::plugin::Plugin;
use autumn_web::plugin_contract::PluginContract;
use autumn_web::reexports::axum::Router;
use autumn_web::reexports::axum::extract::FromRequestParts;
use autumn_web::reexports::http::request::Parts;
use autumn_web::route_listing::RouteInfo;
use autumn_web::{AppState, AutumnError, AutumnResult};

use crate::client::{RetryPolicy, ShopifyClient};
use crate::config::ShopifyConfig;
use crate::delivery::{DeliveryStore, InMemoryDeliveryStore};
use crate::error::{Error, Result};
use crate::tokens::{InMemoryTokenStore, ShopToken, TokenStore};
use crate::types::{ApiVersion, ShopDomain};
use crate::verify::SecretSet;
use crate::webhooks::{IntoWebhookHandler, WebhookHandler, WebhookRegistry};

/// The `autumn-web` range this plugin supports. Keep it equal to the
/// `autumn-web` requirement in `Cargo.toml`.
const SUPPORTED_AUTUMN_WEB: &str = "0.8";

/// `client_for` refreshes a token that expires within this many seconds.
pub const REFRESH_MARGIN_SECS: i64 = 60;

/// After a failed refresh, callers use the old token (while it is valid)
/// for this many seconds before the next try.
pub const REFRESH_BACKOFF_SECS: i64 = 10;

/// A builder closure for [`ShopifyPlugin::configure`].
type ConfigureFn = Arc<dyn Fn(&mut ShopifyConfig) + Send + Sync + 'static>;

/// The future an install handler returns.
pub type InstallFuture = Pin<Box<dyn Future<Output = AutumnResult<()>> + Send + 'static>>;

/// A type-erased install handler.
pub type InstallHandler = Arc<dyn Fn(InstallContext) -> InstallFuture + Send + Sync + 'static>;

/// What an install handler receives. The token is already stored.
#[derive(Clone)]
#[non_exhaustive]
pub struct InstallContext {
    /// The shop that installed the app.
    pub shop: ShopDomain,
    /// The granted scopes, comma-separated.
    pub scope: String,
    /// The app state.
    pub state: AppState,
    /// The plugin handle. `client_for(&shop)` works at once.
    pub shopify: Shopify,
}

impl std::fmt::Debug for InstallContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallContext")
            .field("shop", &self.shop)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// The per-shop refresh state, behind the per-shop lock.
#[derive(Debug, Default)]
struct RefreshState {
    failed_at: Option<i64>,
}

/// Token work: storage, refresh, install, and uninstall, serialized per
/// shop. It lives behind an `Arc`, so that a refresh can run in its own
/// task.
pub(crate) struct Keeper {
    http: reqwest::Client,
    admin_base_url: Option<String>,
    api_key: Option<String>,
    secret: String,
    tokens: Arc<dyn TokenStore>,
    locks: Mutex<HashMap<ShopDomain, Arc<tokio::sync::Mutex<RefreshState>>>>,
}

impl Keeper {
    /// The shared HTTP pool.
    pub(crate) const fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// The client id, for token calls.
    pub(crate) fn api_key(&self) -> Result<&str> {
        self.api_key
            .as_deref()
            .ok_or_else(|| Error::Config("token calls need [shopify] api_key".to_owned()))
    }

    /// The current client secret, for token calls.
    pub(crate) fn secret(&self) -> &str {
        &self.secret
    }

    /// The origin for Admin API and OAuth calls to `shop`.
    pub(crate) fn admin_origin(&self, shop: &ShopDomain) -> String {
        self.admin_base_url.as_deref().map_or_else(
            || format!("https://{shop}"),
            |base| base.trim_end_matches('/').to_owned(),
        )
    }

    /// The lock for `shop`.
    fn lock_for(&self, shop: &ShopDomain) -> Result<Arc<tokio::sync::Mutex<RefreshState>>> {
        let mut locks = self.lock_table()?;
        Ok(Arc::clone(locks.entry(shop.clone()).or_default()))
    }

    fn lock_table(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<ShopDomain, Arc<tokio::sync::Mutex<RefreshState>>>>>
    {
        self.locks
            .lock()
            .map_err(|_| Error::Store("token lock table is poisoned".to_owned()))
    }

    /// A token for `shop` that is fresh at `now`. Refreshes it when needed.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the per-shop lock must cover the read, the refresh, and the write"
    )]
    async fn fresh_token(&self, shop: &ShopDomain, now: i64) -> Result<ShopToken> {
        let lock = self.lock_for(shop)?;
        let mut state = lock.lock().await;
        let token = self
            .tokens
            .get(shop)
            .await?
            .ok_or_else(|| Error::NotInstalled(shop.to_string()))?;
        if !token.needs_refresh(now, REFRESH_MARGIN_SECS) {
            return Ok(token);
        }
        let backing_off = state
            .failed_at
            .is_some_and(|at| now.saturating_sub(at) < REFRESH_BACKOFF_SECS);
        if backing_off && !token.is_expired(now) {
            return Ok(token);
        }
        let Some(refresh) = token
            .refresh_token
            .clone()
            .filter(|_| token.can_refresh(now))
        else {
            self.delete_if_unchanged(shop, &token).await?;
            return Err(Error::Reauthorize(shop.to_string()));
        };
        match crate::oauth::refresh_token(self, shop, &refresh, now).await {
            Ok(mut fresh) => {
                fresh.installed_at = token.installed_at;
                self.tokens.put(shop, fresh.clone()).await?;
                state.failed_at = None;
                tracing::info!(shop = %shop, "shopify token refreshed");
                Ok(fresh)
            }
            Err(Error::Reauthorize(_)) => {
                self.delete_if_unchanged(shop, &token).await?;
                tracing::warn!(shop = %shop, "shopify refused the refresh token; the shop must install again");
                Err(Error::Reauthorize(shop.to_string()))
            }
            Err(err) => {
                state.failed_at = Some(now);
                if token.is_expired(now) {
                    Err(err)
                } else {
                    tracing::warn!(shop = %shop, error = %err, "shopify refresh failed; the old token is still valid");
                    Ok(token)
                }
            }
        }
    }

    /// Delete the token of `shop` only when the store still holds `seen`.
    /// Another replica or a new install can have replaced it.
    async fn delete_if_unchanged(&self, shop: &ShopDomain, seen: &ShopToken) -> Result<()> {
        if self.tokens.get(shop).await?.as_ref() == Some(seen) {
            self.tokens.delete(shop).await?;
        }
        Ok(())
    }

    /// Store the token from an install.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the per-shop lock must cover the write"
    )]
    pub(crate) async fn store_install(&self, shop: &ShopDomain, token: ShopToken) -> Result<()> {
        let lock = self.lock_for(shop)?;
        let mut state = lock.lock().await;
        self.tokens.put(shop, token).await?;
        state.failed_at = None;
        Ok(())
    }

    /// Delete the token of `shop` for an event at `event_at` (Unix seconds).
    ///
    /// A token from an install after the event stays. Returns `true` when
    /// the token is gone.
    pub(crate) async fn delete_for_event(
        &self,
        shop: &ShopDomain,
        event_at: Option<i64>,
    ) -> Result<bool> {
        let lock = self.lock_for(shop)?;
        let guard = lock.lock().await;
        let current = self.tokens.get(shop).await?;
        let newer = matches!(
            (current.as_ref().and_then(|t| t.installed_at), event_at),
            (Some(installed), Some(event)) if installed > event
        );
        if newer {
            return Ok(false);
        }
        self.tokens.delete(shop).await?;
        drop(guard);
        self.lock_table()?.remove(shop);
        Ok(true)
    }
}

/// Runtime state shared by the routes and the [`Shopify`] extractor.
///
/// The startup hook puts it in the [`AppState`] extensions.
pub struct ShopifyRuntime {
    config: ShopifyConfig,
    secrets: SecretSet,
    api_version: ApiVersion,
    single_store: Option<(ShopDomain, String)>,
    retry: RetryPolicy,
    registry: WebhookRegistry,
    deliveries: Arc<dyn DeliveryStore>,
    on_install: Option<InstallHandler>,
    keeper: Arc<Keeper>,
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
    pub(crate) const fn secrets(&self) -> &SecretSet {
        &self.secrets
    }

    /// The webhook handlers.
    #[must_use]
    pub const fn registry(&self) -> &WebhookRegistry {
        &self.registry
    }

    /// The token store.
    #[must_use]
    pub fn token_store(&self) -> &Arc<dyn TokenStore> {
        &self.keeper.tokens
    }

    /// The duplicate-delivery store.
    #[must_use]
    pub const fn delivery_store(&self) -> &Arc<dyn DeliveryStore> {
        &self.deliveries
    }

    /// The install handler, if set.
    pub(crate) const fn on_install(&self) -> Option<&InstallHandler> {
        self.on_install.as_ref()
    }

    /// The token keeper.
    pub(crate) fn keeper(&self) -> &Keeper {
        &self.keeper
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
            self.keeper.http.clone(),
            shop.clone(),
            self.api_version.clone(),
            token,
        )
        .with_base_url(self.keeper.admin_origin(shop))
        .with_retry(self.retry)
    }

    /// The client for `shop`, at Unix time `now`.
    ///
    /// The single-store shop uses the fixed token. Other shops use the
    /// token store. When the token expires within
    /// [`REFRESH_MARGIN_SECS`], it refreshes first. Only one refresh for a
    /// shop runs at a time, in its own task: a cancelled caller does not
    /// lose the new token pair. When a refresh fails and the old token is
    /// still valid, the client uses the old token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInstalled`] when the shop has no token,
    /// [`Error::Reauthorize`] when Shopify refuses the refresh token, or a
    /// store or HTTP error.
    pub async fn client_for(&self, shop: &ShopDomain, now: i64) -> Result<ShopifyClient> {
        if let Some((single, token)) = &self.single_store
            && single == shop
        {
            return Ok(self.make_client(shop, token.clone()));
        }
        let token = self
            .keeper
            .tokens
            .get(shop)
            .await?
            .ok_or_else(|| Error::NotInstalled(shop.to_string()))?;
        if !token.needs_refresh(now, REFRESH_MARGIN_SECS) {
            return Ok(self.make_client(shop, token.access_token));
        }
        let keeper = Arc::clone(&self.keeper);
        let owned = shop.clone();
        let token = tokio::spawn(async move { keeper.fresh_token(&owned, now).await })
            .await
            .map_err(|_| Error::Store("the token refresh task stopped".to_owned()))??;
        Ok(self.make_client(shop, token.access_token))
    }
}

/// The plugin handle for app routes.
///
/// ```no_run
/// use autumn_plugin_shopify::Shopify;
/// use autumn_web::prelude::*;
///
/// #[get("/shop-name")]
/// #[public]
/// async fn shop_name(shopify: Shopify) -> AutumnResult<String> {
///     let client = shopify.client().map_err(|e| e.to_autumn_error())?;
///     let info = client.shop_info().await.map_err(|e| e.to_autumn_error())?;
///     Ok(info.name)
/// }
/// ```
///
/// Extraction fails with 503 when the app does not use the plugin.
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
    /// Returns [`Error::MissingRuntime`] when the app does not use the
    /// plugin.
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

    /// The app state.
    #[must_use]
    pub const fn state(&self) -> &AppState {
        &self.state
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

    /// The local URL that starts an install for `shop`. Send the browser
    /// there on [`Error::NotInstalled`] or [`Error::Reauthorize`].
    #[must_use]
    pub fn install_url(shop: &ShopDomain) -> String {
        format!("{}?shop={shop}", crate::oauth::AUTH_PATH)
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
    on_install: Option<InstallHandler>,
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
    /// A malformed or repeated topic stops the startup.
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

    /// Run `handler` after each install, when the token is stored. Use it
    /// to save a shop record or to subscribe webhooks. An error gives 500;
    /// the token stays stored.
    #[must_use]
    pub fn on_install<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(InstallContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AutumnResult<()>> + Send + 'static,
    {
        self.on_install = Some(Arc::new(move |ctx| Box::pin(handler(ctx))));
        self
    }

    /// Send Admin API and OAuth calls to `base_url` instead of
    /// `https://{shop}`. For tests only: the startup fails unless the host
    /// is `localhost`, `127.0.0.1`, or `[::1]`, because the calls carry the
    /// client secret and the tokens.
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
        if let Some(base) = &self.admin_base_url {
            check_loopback(base)?;
        }
        let retry = RetryPolicy::new(config.max_throttle_retries, RetryPolicy::default().max_wait);
        let keeper = Keeper {
            http: crate::client::http_client()?,
            admin_base_url: self.admin_base_url.clone(),
            api_key: config.api_key.clone(),
            secret: secrets.current().to_owned(),
            tokens: self
                .token_store
                .clone()
                .unwrap_or_else(|| Arc::new(InMemoryTokenStore::new())),
            locks: Mutex::new(HashMap::new()),
        };
        Ok(ShopifyRuntime {
            secrets,
            api_version,
            single_store,
            retry,
            registry,
            deliveries: self
                .delivery_store
                .clone()
                .unwrap_or_else(|| Arc::new(InMemoryDeliveryStore::default())),
            on_install: self.on_install.clone(),
            keeper: Arc::new(keeper),
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
            // Health only, not readiness: a Shopify outage must not take
            // the app out of the load balancer, or webhooks fail too. No
            // retries: a probe must answer fast.
            let client = client.with_retry(RetryPolicy::new(0, std::time::Duration::ZERO));
            // A duplicate name means the app adds the plugin twice. The
            // framework already warns about that.
            let _ = state.health_indicator_registry().register(
                "shopify",
                IndicatorGroup::HealthOnly,
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

/// Startup warnings: compliance topics with no handler (OAuth on), a
/// half-set single-store mode, and a webhook path that CSRF checks block.
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
    let config = runtime.config();
    if config.shop.is_some() != config.access_token().is_some() {
        warnings.push(format!(
            "shopify: single-store mode is off; it needs both [shopify] shop and {}",
            crate::config::ACCESS_TOKEN_ENV
        ));
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
/// `autumn routes audit` sees the mount as enumerable. Autumn derives each
/// route classification from `#[public]` on the handler.
pub(crate) fn mount() -> (Router<AppState>, Vec<RouteInfo>) {
    let all_routes: Vec<autumn_web::Route> = crate::webhooks::webhook_routes()
        .into_iter()
        .chain(crate::oauth::oauth_routes())
        .collect();
    // These routes declare no API version, so this call cannot fail.
    let mut infos = autumn_web::route_listing::collect_route_infos(&all_routes, &[], &[], &[])
        .unwrap_or_default();
    for info in &mut infos {
        info.path = format!("/shopify{}", info.path);
    }
    let mut router = Router::<AppState>::new();
    for route in all_routes {
        router = router.route(route.path, route.handler);
    }
    (router, infos)
}

/// Check that `base` is an `http(s)` URL on a loopback host.
fn check_loopback(base: &str) -> Result<()> {
    let url = url::Url::parse(base)
        .map_err(|_| Error::Config(format!("admin_base_url {base:?} is not a valid URL")))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if loopback && matches!(url.scheme(), "http" | "https") {
        Ok(())
    } else {
        Err(Error::Config(
            "admin_base_url is for tests only and must use a loopback host".to_owned(),
        ))
    }
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
