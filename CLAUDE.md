# CLAUDE.md — autumn-plugin-shopify

## Commands

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo +1.88 clippy --locked --all-targets --all-features -- -D warnings   # MSRV
cargo llvm-cov --summary-only                                            # keep >= 85 % lines
```

All gates must pass before a push. `Cargo.lock` is committed.

## Architecture

| Module | Owns | Depends on |
|---|---|---|
| `error` | `Error`, `ErrorKind`, `status()`, `to_autumn_error()` | `autumn_web`, `thiserror` |
| `types` | `ShopDomain`, `Topic`, `ApiVersion` (validated at parse) | `error` |
| `verify` | `SecretSet`, webhook (base64) and query (hex) HMAC | `hmac`, `sha2`, `base64`, `hex` |
| `config` | `ShopifyConfig`: `[shopify]` + `SHOPIFY_*` env | `types`, `verify`, `toml` |
| `tokens` | `ShopToken`, `TokenStore`, `InMemoryTokenStore` | `types` |
| `delivery` | `DeliveryStore`, `InMemoryDeliveryStore` | `tokens::StoreFuture` |
| `client` | `ShopifyClient`, `RetryPolicy`, throttle waits | `reqwest`, `types` |
| `webhooks` | Route, `VerifiedWebhook`, `WebhookRegistry`, `process` | `verify`, `plugin` |
| `oauth` | Install and callback routes, code exchange, refresh | `verify`, `tokens`, `plugin` |
| `health` | `ShopifyHealth` | `client`, `autumn_web::actuator` |
| `plugin` | `ShopifyPlugin`, `ShopifyRuntime`, `Shopify`, `mount`, warnings | all above |

Webhook flow: Shopify `POST`s `/shopify/webhooks` → `VerifiedWebhook`
checks the HMAC on the raw bytes (401) and reads headers (400) →
`process` claims the webhook id (duplicate: 200) → token cleanup for
`app/uninstalled` / `shop/redact` → topic handler → 200, or 500 with the
claim released.

## Rules

- Secrets travel only through `SHOPIFY_API_SECRET`,
  `SHOPIFY_API_SECRET_PREVIOUS`, `SHOPIFY_ACCESS_TOKEN`. Never in
  `autumn.toml`, code, logs, `Debug`, or error text.
- `unsafe_code = "forbid"`. Tests never call `std::env::set_var`: use
  `ShopifyConfig::from_sources` with a lookup closure.
- No `unwrap`/`expect`/`panic!`/`todo!` in production code. Tests may use
  `expect` with a module-level `allow`.
- Never `?` an `Error` into `AutumnError` (the blanket `From` gives 500).
  Call `to_autumn_error()`.
- Build every outbound shop URL from a `ShopDomain`, never from raw input.
- HMAC checks run on raw bytes, before any parsing, and compare in
  constant time.
- Retry only throttled Admin API calls. A mutation must not run twice.
- Time and randomness come from `AppState::clock()` and
  `AppState::entropy()`. Tests use `FixedClock` and `SeededEntropy`.
- `Plugin::build` has no side effects. IO happens in the `on_startup` hook
  (`ShopifyPlugin::start`).
- Unit tests live in `src/<module>/tests.rs`. Network tests use
  `test_support::Stub` (local axum server). No test needs Shopify.
- Docs and comments in ASD-STE100 style: short sentences, active voice,
  simple present tense. `missing_docs` warns.
- `SUPPORTED_AUTUMN_WEB` in `src/plugin.rs` must equal the `autumn-web`
  requirement in `Cargo.toml`.
- Ground Shopify facts on shopify.dev and record them in
  `docs/planning.md`. Never from memory.
