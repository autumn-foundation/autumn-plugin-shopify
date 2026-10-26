# CLAUDE.md — autumn-plugin-shopify

## Commands

```sh
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_BUILD_JOBS=2
export CARGO_TARGET_DIR=~/workspace/autumn-arena/target   # shared with sibling arena builds; never cargo clean
export TMPDIR=~/workspace/.tmp-cargo                      # /tmp is a 512MB tmpfs

cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo +1.88 clippy --locked --all-targets --all-features -- -D warnings   # MSRV
cargo llvm-cov --summary-only                                            # keep >= 85 % lines
```

Run the gates one at a time. Other builds use this machine. All gates must
pass before a push. `Cargo.lock` is committed.

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
| `plugin` | `ShopifyPlugin`, `ShopifyRuntime`, `Keeper` (per-shop token lock), `Shopify`, `InstallContext`, `mount`, warnings | all above |

Webhook flow: Shopify `POST`s `/shopify/webhooks` → `VerifiedWebhook`
checks the HMAC on the raw bytes (401) and reads headers (400) →
`process` claims the webhook id (done: 200, in flight: 409) → a spawned
task runs token cleanup for `app/uninstalled` / `shop/redact` (body shop
must match) and the topic handler → `complete` on success, `release` on an
error or a panic. A dropped request does not stop the task. Both calls
name the claim by its time.

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
- `Plugin::build` has no side effects. IO happens in the `on_startup` hook:
  it reads the config file, then `ShopifyPlugin::start` builds the runtime.
- Every token write and delete goes through `Keeper` and its per-shop lock.
  Never call `TokenStore::put` or `delete` directly in plugin code. Never
  remove an entry from the lock table: one shop keeps one lock.
- Plugin routes carry `#[public]`; `mount` uses `collect_route_infos`, so
  `autumn routes audit` sees a classification. Test it.
- Unit tests live in `src/<module>/tests.rs`. Network tests use
  `test_support::Stub` (local axum server). No test needs Shopify.
- Docs and comments in ASD-STE100 style: short sentences, active voice,
  simple present tense. `missing_docs` warns.
- `SUPPORTED_AUTUMN_WEB` in `src/plugin.rs` must equal the `autumn-web`
  requirement in `Cargo.toml`.
- Ground Shopify facts on shopify.dev and record them in
  `docs/planning.md`. Never from memory.
- Ground Autumn API questions on the docs MCP
  (`~/workspace/skills/autumn-mcp/bin/mcp.py`) or the vendored
  `autumn-web-0.8.0` sources. Never from memory.
