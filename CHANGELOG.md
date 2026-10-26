# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `ShopifyPlugin`: one-line setup for `autumn-web` 0.8. It declares the
  `[shopify]` section, mounts three `#[public]` routes under `/shopify`,
  declares them for `autumn routes audit`, and declares its `autumn-web`
  contract.
- `POST /shopify/webhooks`: base64 HMAC-SHA256 check on the raw body (401 on
  every topic) and a 5 MiB limit (413). A duplicate guard on
  `X-Shopify-Webhook-Id` has three states: a done id gets 200, an id that
  still runs gets 409, a new id runs the handler. The handler runs in its
  own task, so a dropped request does not stop it. Success marks the claim
  done. A failure or a panic releases it, so that the Shopify retry runs.
  A late owner cannot change a newer claim of the same id.
- Token cleanup on `app/uninstalled` and `shop/redact`. The shop in the
  body must match the header. A late event does not delete the token of a
  later install.
- `VerifiedWebhook` extractor, `webhooks::process`, and
  `WebhookContext::{new, client, json}` for custom routes and handler tests.
- OAuth install: `GET /shopify/auth` and `GET /shopify/auth/callback`.
  Stateless `__Host-` state cookie bound to the shop, query HMAC check (on
  the install request too, when Shopify signs it), anchored shop check,
  expiring offline tokens (`expiring=1`), scope check (`write_x` covers
  `read_x`), and `ShopifyPlugin::on_install`.
- Token refresh in `client_for`: 60 s margin, one refresh per shop at a
  time, in its own task. A 401 deletes the token, but only when the store
  still holds the refused pair. When another replica stored a fresh pair,
  the caller uses it. Other failures keep the token. A failed refresh uses
  the old token while it is valid, with a 10 s back-off.
- `TokenStore` and `DeliveryStore` traits with in-memory defaults.
- `ShopifyClient`: Admin GraphQL, typed `query::<T>()`, `shop_info()`,
  `subscribe_webhook()`. Retries only `THROTTLED` and HTTP 429. Follows no
  redirects.
- `Shopify` extractor with `client()`, `client_for()`, `install_url()`.
  A `"shopify"` health indicator (health only, no retries) in single-store
  mode.
- Config: `[shopify]` keys, `SHOPIFY_*` variables, `.configure()` closures.
  Secrets only from the environment; a secret key in the file stops the
  startup. Secret rotation with `SHOPIFY_API_SECRET_PREVIOUS`.
- Startup warnings: missing compliance handlers (OAuth on), half-set
  single-store mode, CSRF on without a `/shopify/webhooks` exemption.
- Test helpers: `sign_webhook`, `sign_query`, `ShopifyConfig::from_sources`,
  `ShopifyPlugin::admin_base_url` (loopback hosts only).
- Example: `shop_app`.
