# autumn-plugin-shopify

Shopify apps on [Autumn](https://autumn-web.app). One line installs:

- **Signed webhooks**, routed by topic, with a duplicate guard.
- **OAuth install** with expiring offline tokens and automatic refresh.
- **An Admin GraphQL client** that retries throttled calls.

## Quickstart

```toml
# Cargo.toml
[dependencies]
autumn-plugin-shopify = { git = "https://github.com/autumn-foundation/autumn-plugin-shopify" }
```

```toml
# autumn.toml
[shopify]
api_key = "<client id>"
app_url = "https://app.example.com"     # turns OAuth on
scopes = ["read_orders", "write_products"]
```

```sh
export SHOPIFY_API_SECRET="<client secret>"
```

```rust
use autumn_plugin_shopify::{ShopifyPlugin, Topic, WebhookContext};
use autumn_web::prelude::*;

async fn order_created(ctx: WebhookContext) -> AutumnResult<()> {
    let order: serde_json::Value = ctx.json().map_err(|e| e.to_autumn_error())?;
    tracing::info!(shop = %ctx.shop, order = %order["id"], "order created");
    Ok(())
}

async fn compliance(ctx: WebhookContext) -> AutumnResult<()> {
    tracing::info!(shop = %ctx.shop, topic = %ctx.topic, "compliance request");
    Ok(())
}

#[autumn_web::main]
async fn main() {
    autumn_web::app()
        .plugin(
            ShopifyPlugin::new()
                .webhook("orders/create", order_created)
                .webhook(Topic::CUSTOMERS_DATA_REQUEST, compliance)
                .webhook(Topic::CUSTOMERS_REDACT, compliance)
                .webhook(Topic::SHOP_REDACT, compliance),
        )
        .run()
        .await;
}
```

In the Shopify Dev Dashboard:

1. Set the redirect URL to `https://<host>/shopify/auth/callback`.
2. Point webhook subscriptions to `https://<host>/shopify/webhooks`.
3. Install on a store: open `https://<host>/shopify/auth?shop=<store>.myshopify.com`.

See `examples/shop_app.rs` for a full app.

## What the plugin installs

| Piece | Detail |
|---|---|
| Config section | `[shopify]`. Secrets come only from the environment. |
| `POST /shopify/webhooks` | Checks the HMAC (401), skips duplicates (200), deletes the token on `app/uninstalled` and `shop/redact`, runs the topic handler. |
| `GET /shopify/auth` | Starts the install: state cookie, then a redirect to Shopify. |
| `GET /shopify/auth/callback` | Checks HMAC, shop, and state; exchanges the code; checks scopes; stores the token. |
| `Shopify` extractor | `client()` for a single store, `client_for(&shop)` for installed shops. |
| Health | A `"shopify"` readiness indicator in single-store mode. |

OAuth routes answer 404 when `app_url` is not set.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `api_key` | none | App client id. OAuth needs it. |
| `shop` | none | The shop of a single-store app. |
| `api_version` | `2026-10` | Admin API version. |
| `scopes` | `[]` | Scopes OAuth asks for. OAuth needs at least one. |
| `app_url` | none | Public base URL. Setting it turns OAuth on. |
| `after_install_path` | `/` | Local path after an install. Gets `?shop=`. |
| `max_throttle_retries` | `3` | Retries for a throttled Admin API call (0–10). |

Environment variables win over the file. `ShopifyPlugin::configure` wins
over both.

| Variable | Holds |
|---|---|
| `SHOPIFY_API_SECRET` | Client secret. Required. |
| `SHOPIFY_API_SECRET_PREVIOUS` | Old client secret, during rotation. |
| `SHOPIFY_ACCESS_TOKEN` | Fixed Admin API token (single-store apps). |
| `SHOPIFY_API_KEY`, `SHOPIFY_SHOP`, `SHOPIFY_API_VERSION`, `SHOPIFY_APP_URL`, `SHOPIFY_SCOPES` | The same values as the file keys. |

A secret key (`api_secret`, `access_token`, `*_secret`, `*_token`) in
`[shopify]` stops the boot.

## Two app shapes

**Single-store (custom) app.** Set `shop` and `SHOPIFY_ACCESS_TOKEN`. Call
`shopify.client()` in a route. The `"shopify"` health indicator checks the
token.

**Public app.** Set `app_url`, `api_key`, and `scopes`. Merchants install
through `/shopify/auth`. Call `shopify.client_for(&shop).await`. The token
refreshes 60 seconds before it expires.

## Calling the Admin API

```rust
use autumn_plugin_shopify::Shopify;
use autumn_web::prelude::*;

#[get("/orders/count")]
async fn order_count(shopify: Shopify) -> AutumnResult<String> {
    let client = shopify.client().map_err(|e| e.to_autumn_error())?;
    let data = client
        .graphql("query { ordersCount { count } }", serde_json::json!({}))
        .await
        .map_err(|e| e.to_autumn_error())?;
    Ok(data["ordersCount"]["count"].to_string())
}
```

`query::<T>()` deserializes `data`. `subscribe_webhook(&topic, url)` creates
a webhook subscription.

The client retries only throttled calls (`THROTTLED` or HTTP 429). Shopify
does not run a throttled call, so a retry is safe. The client does not retry
other failures, because a mutation can run twice.

## Errors

Call `err.to_autumn_error()` to get the right HTTP status. Do not use `?`
to convert an `Error` into `AutumnError`: Autumn's blanket `From` gives 500.

| Kind | Status |
|---|---|
| `Signature`, `NotInstalled`, `Reauthorize` | 401 |
| `InvalidRequest`, `Json` | 400 |
| `StateMismatch`, `ScopeMismatch` | 403 |
| `OAuthDisabled` | 404 |
| `PayloadTooLarge` | 413 |
| `Http`, `ShopifyApi`, `GraphQl` | 502 |
| `Throttled`, `MissingRuntime` | 503 |
| `Config`, `Store` | 500 |

## Production notes

- **Respond fast.** Shopify waits 5 seconds. Enqueue a job for slow work.
  `WebhookContext::state` gives the `AppState`.
- **Bring a store.** `InMemoryTokenStore` and `InMemoryDeliveryStore` lose
  data on restart and do not share data across replicas. Implement
  `TokenStore` and `DeliveryStore` on your database or Redis, and install
  them with `.token_store(...)` and `.delivery_store(...)`.
- **Refresh across replicas.** The plugin runs one refresh per shop in one
  process. Shopify retires the old refresh token, so two replicas that
  refresh at the same time can lose a pair. A shared store must serialize
  refreshes (for example, a row lock).
- **CSRF.** When `security.csrf.enabled` is on, add `/shopify/webhooks` to
  `security.csrf.exempt_paths`. The plugin logs a warning when it is
  missing.
- **Compliance.** Public apps must handle `customers/data_request`,
  `customers/redact`, and `shop/redact`. The plugin logs a warning for each
  missing handler when OAuth is on.
- **Secret rotation.** Put the old secret in `SHOPIFY_API_SECRET_PREVIOUS`
  for at least one hour. Shopify can sign with the old secret for that long.

## Testing your handlers

`sign_webhook(secret, body)` and `sign_query(secret, params)` make requests
the plugin accepts. `ShopifyConfig::from_sources(toml, env_lookup)` builds a
config without the process environment. `ShopifyPlugin::admin_base_url`
points Admin API and OAuth calls at a local stub.

## Crate layout

| Module | Purpose |
|---|---|
| `config` | `[shopify]` config, `SHOPIFY_*` env, builder closures |
| `types` | `ShopDomain`, `Topic`, `ApiVersion` |
| `verify` | Webhook and OAuth HMAC checks |
| `webhooks` | The webhook route, extractor, and topic registry |
| `delivery` | Duplicate-delivery guard |
| `oauth` | Install and callback routes, token exchange, refresh |
| `tokens` | Token storage |
| `client` | Admin GraphQL client |
| `health` | Readiness check |
| `plugin` | `ShopifyPlugin`, `ShopifyRuntime`, `Shopify` |
| `error` | `Error`, `ErrorKind`, HTTP status mapping |

## Not in this release

- Embedded-app session tokens (App Bridge) and token exchange.
- App proxy signature checks.
- Online (per-user) tokens.

## Docs and comments

ASD-STE100 style: short sentences, active voice, simple present tense.

## License

Apache-2.0. See `LICENSE`.
