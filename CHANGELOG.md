# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `ShopifyPlugin`: one-line install for `autumn-web` 0.8. It declares the
  `[shopify]` section, mounts routes under `/shopify`, declares them for
  route audit, and declares its `autumn-web` contract.
- `POST /shopify/webhooks`: base64 HMAC-SHA256 check on the raw body (401 on
  every topic), 5 MiB limit (413), duplicate guard on
  `X-Shopify-Webhook-Id`, token cleanup on `app/uninstalled` and
  `shop/redact`, and topic dispatch. A failed handler gives 500 and frees
  the duplicate claim, so the Shopify retry runs.
- `VerifiedWebhook` extractor and `webhooks::process` for custom routes.
- OAuth install: `GET /shopify/auth` and `GET /shopify/auth/callback`.
  Stateless state cookie, query HMAC check, anchored shop check, expiring
  offline tokens (`expiring=1`), scope check (`write_x` covers `read_x`).
- Token refresh in `client_for`: 60 s margin, one refresh per shop at a
  time, refused refresh deletes the token (`Reauthorize`).
- `TokenStore` and `DeliveryStore` traits with in-memory defaults.
- `ShopifyClient`: Admin GraphQL, typed `query::<T>()`, `shop_info()`,
  `subscribe_webhook()`. Retries only `THROTTLED` and HTTP 429.
- `Shopify` extractor, `"shopify"` readiness indicator (single-store mode).
- Config: `[shopify]` file keys, `SHOPIFY_*` env, `.configure()` closures.
  Secrets only from env; a secret key in the file stops the boot. Secret
  rotation with `SHOPIFY_API_SECRET_PREVIOUS`.
- Startup warnings: missing compliance handlers (OAuth on), CSRF on without
  a `/shopify/webhooks` exemption.
- Test helpers: `sign_webhook`, `sign_query`, `ShopifyConfig::from_sources`,
  `ShopifyPlugin::admin_base_url`.
- Example: `shop_app`.

### Known gaps

- No embedded-app session tokens, app proxy checks, or online tokens.
- In-process refresh lock only; see the README for multi-replica apps.
