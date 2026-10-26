# ADR 0001: Own HMAC checks and a stateless OAuth flow

- Status: accepted
- Date: 2026-10-26

## Context

Autumn 0.8 has `SignedWebhook` with presets for Stripe, GitHub, Slack, and
a generic hex `sha256=` format. Shopify signs webhooks with a base64 digest
and no prefix. Shopify also signs OAuth redirects (hex digest over the
sorted query) and needs 401 for a bad HMAC on compliance topics.

OAuth needs a state nonce. A server-side nonce store breaks across
replicas unless it is shared.

## Decision

1. The plugin owns its HMAC code (`hmac`, `sha2`, `base64`). One module
   (`verify`) holds both checks. Both run on raw input, compare in
   constant time, and accept a previous secret during rotation.
2. The state nonce lives in a browser cookie (`HttpOnly; Secure;
   SameSite=Lax; Path=/shopify/auth; Max-Age=600`). The callback compares
   the `state` parameter to the cookie in constant time. The server keeps
   no OAuth state.
3. Duplicate deliveries and tokens go through traits (`DeliveryStore`,
   `TokenStore`) with in-memory defaults.

## Consequences

- Shopify support does not wait for an Autumn preset. A future Autumn
  Shopify preset can replace `verify::verify_webhook`.
- OAuth works across replicas with no shared store.
- Multi-replica apps must supply shared stores. The README says so.
- A refresh lock is per process. A shared token store must serialize
  refreshes.

## Alternatives

- Autumn `generic` preset: rejected. It expects hex and a `sha256=` prefix.
- Server-side nonce store: rejected. It needs a shared store.
- A signed (HMAC) state cookie: not needed. The cookie value only has to
  equal the `state` parameter; an attacker cannot set a cookie in the
  victim browser for this host.
