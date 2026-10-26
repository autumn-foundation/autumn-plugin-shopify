# Planning — autumn-plugin-shopify

## Goal

Give an Autumn app a safe, one-line Shopify integration:

- Receive signed Shopify webhooks and route them by topic.
- Install the app on a shop with OAuth and keep its access token fresh.
- Call the Admin GraphQL API with throttle-aware retries.

The design follows `autumn-plugin-discord`: config section, startup hook,
routes under one prefix, a health indicator, and typed errors.

## Grounding (2026-10-26)

Checked against shopify.dev and the vendored `autumn-web-0.8.0` sources.

| Fact | Source |
|---|---|
| Webhook HMAC: `X-Shopify-Hmac-Sha256`, base64 HMAC-SHA256 of the raw body, key = app client secret. | shopify.dev, "Deliver webhooks through HTTPS" |
| Duplicate deliveries: dedupe on `X-Shopify-Webhook-Id`; answer 200 for a duplicate. `X-Shopify-Event-Id` correlates, it does not dedupe. | same |
| Shopify waits 5 s, retries 8 times over 4 h, then deletes API-made subscriptions. Non-2xx (3xx too) is a failure. | same |
| A new client secret can take up to 1 h to sign webhooks. | same |
| Compliance topics: `customers/data_request`, `customers/redact`, `shop/redact`. Bad HMAC must get `401`. | shopify.dev, "Privacy law compliance" |
| OAuth callback HMAC: drop `hmac`, sort params, join `k=v` with `&`, hex HMAC-SHA256, constant-time compare. | shopify.dev, "Authorization code grant" |
| Shop regex: `^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$`, anchored at both ends. | same |
| Token exchange: form POST `https://{shop}/admin/oauth/access_token` with `client_id`, `client_secret`, `code`, `expiring=1`. Response: `access_token`, `scope`, `expires_in`, `refresh_token`, `refresh_token_expires_in`. | same |
| Refresh: same URL, `grant_type=refresh_token`. Rotate the pair. A `401` means "clear the pair and re-authorize". | same |
| A `write_*` scope includes its `read_*` scope. Merchants can change scopes: verify them. | same |
| API versions: quarterly (`01`, `04`, `07`, `10`). Latest stable: `2026-10`. Unsupported versions fall forward. | shopify.dev, "API versioning" |
| GraphQL cost: `extensions.cost.throttleStatus { maximumAvailable, currentlyAvailable, restoreRate }`. Backoff of 1 s is the recommendation. Throttled requests do not run. | shopify.dev, "Rate limits" |
| Autumn has no Shopify preset in `SignedWebhook` (Stripe, GitHub, Slack, generic hex only). | `autumn-web-0.8.0/src/webhook.rs` |
| `AppState::entropy()` (OS CSPRNG, seedable) and `AppState::clock()` are the randomness and time seams. | `autumn-web-0.8.0/src/state.rs` |
| `AppState::config()` exposes `security.csrf` (off by default). Plugins cannot add CSRF exemptions. | `autumn-web-0.8.0/src/app.rs` |
| `AutumnError::with_status` sets any status (used for 413 and 502). | `autumn-web-0.8.0/src/error.rs` |

## Brainstorming (what can the plugin do?)

Raw ideas, then the cut:

1. Webhook HMAC verify extractor. **In.**
2. Topic router: `.webhook("orders/create", handler)`. **In.**
3. Duplicate delivery guard on `X-Shopify-Webhook-Id`. **In.**
4. Compliance topics with the 401 rule and a startup warning when they have no handler. **In.**
5. Auto-delete the token on `app/uninstalled` and `shop/redact`. **In.**
6. OAuth install (authorization code grant) with a stateless state cookie. **In.**
7. Expiring offline tokens with refresh and rotation. **In.**
8. Pluggable `TokenStore` (in-memory default). **In.**
9. Admin GraphQL client, typed `query<T>`, throttle retry. **In.**
10. `webhookSubscriptionCreate` helper with topic → enum mapping. **In.**
11. Health indicator for single-store apps. **In.**
12. `Shopify` extractor for app handlers. **In.**
13. Secret rotation (`SHOPIFY_API_SECRET_PREVIOUS`). **In.**
14. Test helpers to sign webhooks and OAuth queries. **In** (`sign_webhook`, `sign_query`).
15. Embedded-app session tokens (App Bridge JWT) and token exchange. Out (v0.2).
16. App proxy signature verification. Out (v0.2).
17. REST Admin client. Out: REST is legacy; GraphQL covers it.
18. Bulk operations, Storefront API, billing API helpers. Out.
19. A Diesel token store. Out: the trait lets apps bring one.
20. Online (per-user) tokens. Out.

## Reverse brainstorming (how do we make it fail?)

Each "how to break it" maps to a guard and an AC.

| How to break it | Guard | AC |
|---|---|---|
| Parse JSON before HMAC, so re-encoding changes the bytes. | Verify on raw bytes first. | AC-11 |
| Compare HMACs with `==` and leak timing. | `subtle` constant-time compare (via `hmac::verify_slice`). | AC-09 |
| Return 400 for a bad HMAC on a compliance topic; app review fails. | Any HMAC failure is 401. | AC-10 |
| Accept `shop.myshopify.com.evil.com` and send the client secret there. | Anchored regex in `ShopDomain`; token exchange URL built only from a `ShopDomain`. | AC-07 |
| Trust a forged OAuth callback. | Verify query HMAC, then state cookie. | AC-29 |
| CSRF on the callback (attacker's code into victim session). | State nonce bound to a browser cookie, compared in constant time. | AC-28, AC-29 |
| Predictable nonce. | 16 bytes from `AppState::entropy()` (OS CSPRNG). | AC-28 |
| Merchant drops a scope; app later fails at random. | Check granted scopes; `write_x` covers `read_x`. | AC-29 |
| Handler fails, guard keeps the ID, Shopify retry is skipped as a duplicate. Data is lost. | Release the claim on handler error. | AC-14 |
| Answer 500 for an unknown topic; Shopify deletes the subscription after 8 tries. | Unknown topic: 200 and a warning. | AC-16 |
| Two requests refresh the same token at once; rotation retires the first new token. | Per-shop single-flight lock in the runtime. | AC-31 |
| Refresh token expired; app loops on errors. | Refresh 401: delete the pair, return `Reauthorize`. | AC-31 |
| Retry a failed mutation on 5xx and charge twice. | Retry only throttles (not run by Shopify). | AC-24 |
| Retry forever while throttled. | `max_throttle_retries` and a wait cap. | AC-24 |
| Secret in `autumn.toml` gets committed. | Any secret key in `[shopify]` fails config loading. | AC-02 |
| Token in logs through `Debug`. | Redacting `Debug` on config, client, token, runtime. | AC-03, AC-27 |
| Huge body exhausts memory. | 5 MiB limit, 413. | AC-11 |
| Rotate the client secret; webhooks fail for up to 1 h. | Verify with current and previous secret. | AC-09 |
| CSRF middleware on; every webhook gets 403. | Startup warning that names the exempt path to add. | AC-36 |
| Uninstalled shop keeps a live token. | `app/uninstalled` and `shop/redact` delete it. | AC-18 |
| Slow handler; Shopify times out at 5 s and retries. | Docs: enqueue a job. Context carries `AppState`. | AC-21 |

## Six thinking hats

- **White (facts).** See Grounding. Shopify needs 2xx within 5 s, 401 for a
  bad HMAC on compliance topics, and verified scopes. Offline tokens now
  expire (`expiring=1`). Autumn has no Shopify HMAC preset.
- **Red (feelings).** Webhook security must feel boring and safe: one
  extractor, fail closed, nothing to configure wrong. OAuth must "just work"
  for a first install.
- **Black (risks).** Multi-replica apps: the in-memory duplicate guard and
  token store do not share state. Mitigation: both are traits; docs say so.
  In-process single-flight does not stop two replicas refreshing at once.
  Mitigation: documented; a shared store must serialize refresh. Shopify can
  change the HMAC join rules for OAuth; mitigation: follow the documented
  rule and test with fixed vectors.
- **Yellow (benefits).** One line installs webhooks, OAuth, and a client.
  Test helpers (`sign_webhook`, `sign_query`) let app authors test their own
  handlers with no Shopify account. Deterministic tests through Autumn's
  entropy and clock seams.
- **Green (alternatives).** (a) Wrap Autumn's `SignedWebhook` with a
  generic preset: rejected, it expects hex and a `sha256=` prefix.
  (b) Server-side nonce store: rejected, it breaks across replicas; the
  cookie is stateless. (c) REST client: rejected, legacy. (d) Make OAuth a
  separate feature flag: rejected for v0.1, it adds no dependency.
- **Blue (process).** Plan → RED (tests compile, fail) → GREEN (minimal
  code) → REFACTOR → multi-angle review → fix → AC evidence table. Gates:
  `fmt`, `clippy -D warnings` (pedantic, nursery), tests, MSRV 1.88,
  coverage ≥ 85 %.

## Decisions

- Own HMAC code (`hmac` + `sha2` + `base64`), not Autumn's `SignedWebhook`.
- Secrets only from the environment: `SHOPIFY_API_SECRET`,
  `SHOPIFY_API_SECRET_PREVIOUS`, `SHOPIFY_ACCESS_TOKEN`.
- OAuth is on when `app_url` is set. Then `api_key` and `scopes` are
  required. Routes always mount; OAuth routes answer 404 when OAuth is off.
- Single-store mode is on when `shop` and `SHOPIFY_ACCESS_TOKEN` are set. It
  adds the `"shopify"` readiness indicator.
- Default API version: `2026-10`.
- Webhook handler errors give 500 so that Shopify retries.
- Duplicate guard window: 24 h, capacity 10 000, oldest out first.
- Time and randomness come from `AppState::clock()` and `AppState::entropy()`.
- No `Plugin::build` side effects. All IO happens in the startup hook.

## Acceptance criteria

### Config

- **AC-01** `[shopify]` is read from `autumn.toml` (`AUTUMN_MANIFEST_DIR`,
  then CWD): `api_key`, `shop`, `api_version` (default `2026-10`), `scopes`,
  `app_url`, `after_install_path` (default `/`), `max_throttle_retries`
  (default 3). Unknown keys fail.
- **AC-02** A secret key (`api_secret`, `client_secret`, `access_token`,
  `secret`, `token`) in `[shopify]` fails config loading.
- **AC-03** Secrets come only from `SHOPIFY_API_SECRET`,
  `SHOPIFY_API_SECRET_PREVIOUS`, `SHOPIFY_ACCESS_TOKEN`. `Debug` redacts them.
- **AC-04** Precedence: builder `.configure()` > `SHOPIFY_*` env
  (`SHOPIFY_API_KEY`, `SHOPIFY_SHOP`, `SHOPIFY_API_VERSION`,
  `SHOPIFY_APP_URL`, `SHOPIFY_SCOPES`) > file > defaults.
- **AC-05** `validate` needs the API secret; checks the shop domain, the API
  version format (`YYYY-01|04|07|10` or `unstable`), and, with OAuth on,
  `api_key`, non-empty `scopes`, and an `https` `app_url` (`http` only for
  `localhost`/`127.0.0.1`).
- **AC-06** Invalid config fails app startup with a clear message.

### Domain types

- **AC-07** `ShopDomain::parse` accepts only the anchored myshopify pattern
  and lowercases it. Property-tested.
- **AC-08** `Topic::parse` accepts lowercase `seg/seg[/seg]` with
  `[a-z0-9_]`; `graphql_enum()` maps `orders/create` → `ORDERS_CREATE`.

### Webhook verification

- **AC-09** Base64 HMAC-SHA256 of the raw body; constant-time compare;
  current or previous secret.
- **AC-10** Missing, malformed, or wrong HMAC → 401, on every topic.
- **AC-11** HMAC check runs on raw bytes before parsing; body > 5 MiB → 413.
- **AC-12** After a valid HMAC, a missing topic, shop, or webhook-id header,
  or a bad shop domain, gives 400.

### Webhook dispatch

- **AC-13** `POST /shopify/webhooks` runs the handler for the topic; Ok → 200.
- **AC-14** Handler error → 500 and the duplicate claim is released.
- **AC-15** A repeated webhook id → 200, handler does not run again.
- **AC-16** Unknown topic → 200 and a warning; no handler runs.
- **AC-17** A duplicate or invalid topic registration fails startup.
- **AC-18** `app/uninstalled` and `shop/redact` delete the shop's token
  before the app handler runs.
- **AC-19** With OAuth on, startup warns for each compliance topic that has
  no handler.
- **AC-20** The `VerifiedWebhook` extractor works on custom routes.
- **AC-21** `WebhookContext` gives topic, shop, webhook id, event id, API
  version, triggered-at, raw body, `json::<T>()`, `AppState`, and a
  `Shopify` handle.

### Admin API client

- **AC-22** `graphql(query, variables)` posts to
  `{base}/admin/api/{version}/graphql.json` with `X-Shopify-Access-Token`
  and returns `data`.
- **AC-23** GraphQL `errors` → `Error::GraphQl`; non-2xx →
  `Error::ShopifyApi { status, body }` (body truncated to 500 chars).
- **AC-24** `THROTTLED` and HTTP 429 retry up to `max_throttle_retries`.
  Wait comes from `throttleStatus` or `Retry-After`, default 1 s, capped.
  Nothing else retries.
- **AC-25** `query::<T>()` deserializes `data` into `T`.
- **AC-26** `shop_info()` returns shop name and domain.
  `subscribe_webhook(topic, url)` calls `webhookSubscriptionCreate` and
  surfaces `userErrors`.
- **AC-27** The access token never shows in `Debug` or error text.

### OAuth

- **AC-28** `GET /shopify/auth?shop=` checks the shop, mints a 16-byte nonce
  from `AppState::entropy()`, sets an `HttpOnly; Secure; SameSite=Lax`
  cookie on `/shopify/auth`, and redirects (302) to the authorize URL with
  `client_id`, `scope`, `redirect_uri`, `state`. Bad shop → 400. OAuth off
  → 404.
- **AC-29** `GET /shopify/auth/callback` checks the query HMAC (401), the
  shop (400), the state against the cookie (403), exchanges the code with
  `expiring=1`, checks scopes (403), stores the token, clears the cookie,
  and redirects to `after_install_path?shop=`.
- **AC-30** `TokenStore` trait (`get`, `put`, `delete`) with
  `InMemoryTokenStore` as default; `.token_store(...)` replaces it.
- **AC-31** `client_for(shop)` refreshes a token within 60 s of expiry,
  stores the new pair, and runs one refresh per shop at a time. Refresh 401
  → token deleted, `Error::Reauthorize`.
- **AC-32** Token exchange failure gives 502 with no secret in the message.

### Plugin and runtime

- **AC-33** `ShopifyPlugin` declares `[shopify]`, mounts routes under
  `/shopify`, declares them for route audit, declares the `autumn-web 0.8`
  contract, and passes `plugin_conformance`.
- **AC-34** The `Shopify` extractor gives `client()` (single-store) and
  `client_for(shop)`; no runtime → 503.
- **AC-35** Single-store mode registers a `"shopify"` readiness indicator:
  Up with the shop name, Down with the error.
- **AC-36** Startup warns when CSRF is on and `/shopify/webhooks` is not
  exempt.

### Quality

- **AC-37** No `unwrap`/`expect`/`panic`/`todo` in production code;
  `unsafe_code = "forbid"`; `missing_docs` warns.
- **AC-38** `fmt`, `clippy --all-targets --all-features -D warnings`, and
  tests pass with `--locked`; builds on MSRV 1.88.
- **AC-39** Tests need no Shopify account or network (local stubs only).
- **AC-40** README, CHANGELOG, CLAUDE.md, ADR, and an example; ASD-STE100
  style.
- **AC-41** Line coverage ≥ 85 %.
- **AC-42** CI runs the gates.

## Test strategy

- `verify`: fixed HMAC vectors, tamper, wrong key, previous key, malformed
  base64/hex, property test "sign then verify".
- `shop`: property tests over valid and hostile domains; topic mapping.
- `config`: TOML parsing and env layering through a lookup closure (no
  process env changes: `unsafe_code = "forbid"`).
- `client`, `oauth`, `health`: a local axum stub server records requests and
  serves scripted answers.
- `webhooks`, `oauth` routes: `TestApp::from_router` with a hand-built
  runtime, a seeded entropy source, and a fixed clock.
- `plugin`: builder, contract, conformance harness.

## Future work

- Embedded-app session tokens and token exchange.
- App proxy signature verification.
- Shared (Redis/DB) duplicate guard and token store examples.

## Review round 1 (2026-10-26)

Four reviewers (security, correctness, Shopify spec, API/docs) read the
code. Their confirmed findings added these ACs.

- **AC-43** The handler runs in its own task. A panic or a dropped request
  releases the claim (`complete` on success, `release` otherwise).
- **AC-44** A claim has three states. A repeated id that still runs gets
  409; an in-flight claim expires after a 5 min lease.
- **AC-45** Before it deletes a token, the plugin checks the shop in the
  body (`myshopify_domain` / `shop_domain`) against the header (400 on a
  mismatch).
- **AC-46** A late `app/uninstalled` or `shop/redact` keeps the token of a
  later install (`installed_at` > `X-Shopify-Triggered-At`).
- **AC-47** Only a refresh 401 that is not `invalid_client` deletes the
  token, and only when the store still holds the refused pair.
- **AC-48** A refresh runs in its own task. A cancelled caller does not
  lose the rotated pair. Uninstall and install writes take the same
  per-shop lock, so a refresh cannot bring back a deleted token.
- **AC-49** A failed refresh returns the old token while it is valid, with
  a 10 s back-off.
- **AC-50** The OAuth query HMAC follows the shopify.dev rule (drop
  `hmac`, sort, join decoded `k=v` with `&`). The install request HMAC is
  checked when present.
- **AC-51** The state cookie is `__Host-` and binds the shop. A repeated
  cookie is refused.
- **AC-52** Plugin routes are `#[public]` and pass `autumn routes audit`
  (classification `Public`).
- **AC-53** The health indicator is health-only (not readiness) and does
  not retry.
- **AC-54** `admin_base_url` accepts only loopback hosts. The HTTP client
  follows no redirects.
- **AC-55** Topics with dots (`customer.tags_added`) parse.
  `subscribe_webhook` refuses compliance topics.
- **AC-56** `on_install` hook and `Shopify::install_url`.
- **AC-57** `after_install_path` with a query joins with `&`; a fragment is
  refused. `SHOPIFY_AFTER_INSTALL_PATH` and `SHOPIFY_MAX_THROTTLE_RETRIES`
  exist.
- **AC-58** Public structs and enums that can grow are `#[non_exhaustive]`
  with constructors (`RetryPolicy::new`, `ShopToken::with_refresh`,
  `WebhookContext::new`).

Rejected or deferred, with the reason:

- Dedupe on a body hash (header-swap replay): two subscriptions can send
  equal bodies. AC-45 covers the damaging case. Documented as "unsigned
  headers".
- Try the previous secret on a refresh `invalid_client`: the token is kept
  (AC-47), so a rotation error is not destructive. Deferred.
- Wrap `reqwest::Error` in `Error::Http`: the sibling plugins expose it
  too. Deferred to a breaking release.
- Autumn profile layering: documented as a gap.
