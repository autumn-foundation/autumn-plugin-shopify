# Acceptance criteria and evidence

Each row names the AC from `docs/planning.md` and the evidence that it is
met. Test names are in `src/<module>/tests.rs` (`module::test`). "Smoke"
means the live run of `examples/shop_app` over HTTP (2026-10-26). Status
on 2026-10-26: all met, no open gaps.

## Config

| AC | Criterion | Evidence |
|---|---|---|
| AC-01 | `[shopify]` keys, defaults, unknown keys fail | `config::toml_section_sets_every_field`, `defaults_are_documented_values`, `unknown_keys_and_bad_toml_fail`, `missing_section_gives_defaults`; file discovery (`AUTUMN_MANIFEST_DIR`) in smoke |
| AC-02 | Secret keys in the file fail | `config::secret_keys_in_the_file_fail_closed` (the value never shows in the error) |
| AC-03 | Secrets only from env, `Debug` redacts | `config::env_overrides_file_and_carries_secrets`, `debug_redacts_secrets`, `verify::secret_set_debug_redacts`, `plugin::runtime_debug_hides_secrets` |
| AC-04 | Precedence builder > env > file > defaults | `config::env_overrides_file_and_carries_secrets`, `blank_env_values_count_as_unset`, `plugin::configure_closures_win_over_env` |
| AC-05 | `validate` rules | `config::validate_needs_the_secret`, `validate_checks_shop_and_version`, `validate_checks_oauth_fields`, `validate_bounds_retries`, `webhooks_only_config_validates_without_oauth_fields` |
| AC-06 | Bad config stops the startup | `plugin::start_fails_on_a_bad_config`, `build_runtime_needs_a_valid_config` |

## Domain types

| AC | Criterion | Evidence |
|---|---|---|
| AC-07 | Anchored shop domain | `types::shop_domain_rejects_hostile_values`, `shop_domain_does_not_trim`, `shop_domain_rejects_overlong_values`; property tests `shop_domain_accepts_every_valid_label`, `shop_domain_never_accepts_a_suffix`, `parsed_shop_is_always_lowercase_myshopify` |
| AC-08 | Topic parse and enum mapping | `types::topic_parses_and_maps_to_graphql_enum`, `topic_rejects_malformed_values`, `topic_flags_compliance_topics` |

## Webhook verification

| AC | Criterion | Evidence |
|---|---|---|
| AC-09 | Base64 HMAC, constant time, previous secret | `verify::sign_webhook_matches_reference_vector` (Python reference), `verify_webhook_accepts_previous_secret_during_rotation`, property tests `signed_webhooks_always_verify`, `a_flipped_body_bit_never_verifies`; constant time: `hmac::Mac::verify_slice` in `verify::verify_digest` |
| AC-10 | Any HMAC failure is 401 on every topic | `webhooks::hmac_failures_are_401_on_every_topic` (incl. the 3 compliance topics); smoke: 401 on `customers/redact` |
| AC-11 | HMAC on raw bytes first; > 5 MiB is 413 | `webhooks::a_changed_body_is_401`, `hmac_runs_before_header_checks`, `an_oversized_body_is_413`, `verify::verify_webhook_rejects_tampered_body` |
| AC-12 | Missing or bad headers are 400 | `webhooks::missing_or_bad_headers_are_400` |

## Webhook dispatch

| AC | Criterion | Evidence |
|---|---|---|
| AC-13 | Topic handler runs, 200 | `webhooks::a_valid_delivery_runs_the_handler_with_full_context`; smoke |
| AC-14 | Handler error is non-2xx, claim released | `webhooks::a_failed_handler_is_500_and_its_retry_runs_again`, `a_store_failure_is_500_and_releases_the_claim` |
| AC-15 | Done duplicate is 200, no rerun | `webhooks::a_duplicate_webhook_id_is_200_and_runs_nothing`; smoke |
| AC-16 | Unknown topic is 200 | `webhooks::an_unknown_topic_is_200_and_runs_nothing` |
| AC-17 | Bad or repeated topic stops the startup | `webhooks::registry_rejects_bad_and_repeated_topics`, `plugin::build_runtime_rejects_bad_and_repeated_topics` |
| AC-18 | Uninstall and shop redact delete the token first | `webhooks::app_uninstalled_deletes_the_token_first`, `shop_redact_deletes_the_token_first`, `uninstall_without_a_handler_still_deletes_the_token` |
| AC-19 | Warning per missing compliance handler | `plugin::warnings_name_missing_compliance_handlers_when_oauth_is_on` |
| AC-20 | `VerifiedWebhook` on a custom route | `webhooks::the_extractor_works_on_a_custom_route`, `process_reports_each_outcome` |
| AC-21 | `WebhookContext` contents | `webhooks::a_valid_delivery_runs_the_handler_with_full_context`, `webhook_context_new_and_client_work_in_handler_tests` |

## Admin API client

| AC | Criterion | Evidence |
|---|---|---|
| AC-22 | Endpoint, header, `data` | `client::graphql_posts_query_and_returns_data`, `endpoint_defaults_to_the_shop_host` |
| AC-23 | GraphQL and HTTP errors | `client::graphql_errors_surface_their_messages`, `http_errors_keep_status_and_truncate_body` |
| AC-24 | Retry only throttles, capped wait | `client::throttled_graphql_retries_then_succeeds` (asks 20 s, cap 5 ms, elapsed < 2 s), `http_429_retries_then_succeeds`, `throttle_retries_run_out`, `zero_retries_fail_on_the_first_throttle`, `server_errors_do_not_retry`, `throttle_wait_*`, `retry_after_reads_seconds`, `plugin::the_retry_policy_follows_the_config` |
| AC-25 | Typed `query::<T>()` | `client::query_deserializes_data` |
| AC-26 | `shop_info`, `subscribe_webhook` | `client::shop_info_reads_name_and_domain`, `subscribe_webhook_sends_enum_topic_and_returns_id`, `subscribe_webhook_surfaces_user_errors` |
| AC-27 | Token never in `Debug` or errors | `client::debug_redacts_the_token`, `http_errors_keep_status_and_truncate_body`, `health::a_failing_token_reports_down_with_the_error` |

## OAuth

| AC | Criterion | Evidence |
|---|---|---|
| AC-28 | Install redirect and cookie (cookie rules: see AC-51) | `oauth::install_redirects_to_shopify_with_a_state_cookie`, `install_nonce_comes_from_the_app_entropy`, `install_rejects_bad_or_missing_shops`, `oauth_routes_are_404_when_oauth_is_off`; smoke |
| AC-29 | Callback checks and exchange | `oauth::callback_exchanges_the_code_and_stores_the_token` (form has `expiring=1`), `callback_rejects_a_bad_hmac_with_401`, `callback_rejects_a_bad_shop_with_400`, `callback_rejects_a_state_mismatch_with_403`, `callback_rejects_missing_scopes_with_403`, `callback_rejects_repeated_params_and_missing_code`, `missing_scopes_*` |
| AC-30 | `TokenStore` trait, replaceable | `tokens::in_memory_store_puts_gets_and_deletes`; custom stores in `plugin::a_refused_refresh_uses_and_keeps_a_pair_another_replica_stored` and `webhooks::a_store_failure_is_500_and_releases_the_claim` |
| AC-31 | Refresh within 60 s, one at a time | `plugin::client_for_refreshes_a_token_near_expiry`, `client_for_a_fresh_token_makes_no_refresh`, `concurrent_callers_share_one_refresh` (8 callers, 1 call), `an_expired_refresh_token_needs_reinstall_without_a_call` |
| AC-32 | Exchange failure is 502, no secret | `oauth::callback_maps_exchange_failure_to_502_without_secrets` |

## Plugin and runtime

| AC | Criterion | Evidence |
|---|---|---|
| AC-33 | Section, routes, contract, conformance | `plugin::plugin_passes_the_conformance_harness`, `contract_declares_supported_autumn_web_range`, `contract_is_compatible_with_linked_autumn_web`, `plugin_name_is_stable` |
| AC-34 | `Shopify` extractor | `plugin::shopify_handle_reads_the_runtime_and_clock`, `shopify_extractor_is_503_without_runtime`, `single_store_client_uses_the_fixed_token`, `client_needs_single_store_mode`; smoke (`/shops/{shop}`) |
| AC-35 | Health indicator (group: see AC-53) | `health::a_working_token_reports_up_with_the_shop_name`, `a_failing_token_reports_down_with_the_error`, `plugin::start_installs_the_runtime_and_the_health_indicator`, `start_skips_health_without_single_store_mode` |
| AC-36 | CSRF warning | `plugin::warnings_name_the_csrf_exemption` |

## Quality

| AC | Criterion | Evidence |
|---|---|---|
| AC-37 | No unwrap/panic in production, forbid unsafe | `Cargo.toml` `[lints]` (deny `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`; forbid `unsafe_code`); clippy gate clean |
| AC-38 | fmt, clippy, tests, MSRV 1.88 | Local: all gates on stable and `+1.88`. CI `check` job (1.88) green on the PR |
| AC-39 | No Shopify account or network | `test_support::Stub` (local axum); no test reads secrets from the env |
| AC-40 | Docs | `README.md`, `CHANGELOG.md`, `CLAUDE.md`, `docs/adr/0001-*.md`, `docs/planning.md`, `examples/shop_app.rs`; doc examples are `no_run` and compile |
| AC-41 | Coverage ≥ 85 % | `cargo llvm-cov`: 96.6 % lines; each file 91–100 % |
| AC-42 | CI | `.github/workflows/ci.yml` (`check`, `coverage --fail-under-lines 85`), green on the PR |

## Review round 1

| AC | Criterion | Evidence |
|---|---|---|
| AC-43 | Handler in its own task; panic and dropped request safe | `webhooks::a_panicking_handler_is_500_and_its_retry_runs_again`, `a_dropped_request_still_settles_the_claim` |
| AC-44 | Three claim states, 409, lease | `webhooks::a_duplicate_while_the_first_still_runs_is_409`, `delivery::an_expired_lease_lets_a_retry_claim_again`, `a_new_id_is_fresh_and_a_running_one_is_in_flight` |
| AC-45 | Body shop must match header before delete | `webhooks::an_uninstall_for_another_shop_in_the_body_is_400_and_deletes_nothing`, `a_shop_redact_for_another_shop_is_400`; smoke (400) |
| AC-46 | Late event keeps a newer install | `webhooks::a_late_uninstall_keeps_the_token_of_a_reinstall`, `plugin::a_late_uninstall_keeps_a_token_from_a_later_install`, `oauth::callback_exchanges_the_code_and_stores_the_token` (`installed_at`) |
| AC-47 | Compare-and-delete on a refused refresh (see AC-61) | `plugin::a_refused_refresh_deletes_the_token`, `a_refused_refresh_uses_and_keeps_a_pair_another_replica_stored`, `a_refresh_400_keeps_the_token` |
| AC-48 | Refresh survives cancellation; uninstall wins a race | `plugin::a_cancelled_caller_does_not_lose_the_rotated_pair`, `an_uninstall_during_a_refresh_wins` |
| AC-49 | Old token on a failed refresh, back-off | `plugin::a_failed_refresh_uses_the_old_token_while_it_is_valid_and_backs_off`, `a_failed_refresh_keeps_the_token` |
| AC-50 | shopify.dev query HMAC; install HMAC when present | `verify::verify_query_accepts_shopify_doc_example` (published vector), `query_message_sorts_and_drops_hmac`, `query_message_keeps_decoded_values_and_other_params`, `signed_queries_always_verify`, `oauth::install_checks_the_hmac_when_shopify_sends_one` |
| AC-51 | `__Host-` cookie bound to the shop; repeats refused | `oauth::cookies_have_the_hardened_attributes`, `callback_rejects_a_cookie_for_another_shop_or_a_repeated_cookie`, `cookie_value_finds_the_named_cookie` |
| AC-52 | Routes pass `autumn routes audit` | `plugin::every_plugin_route_is_classified_public` |
| AC-53 | Health only, no retries | `plugin::the_health_indicator_is_health_only_and_does_not_retry` |
| AC-54 | Loopback-only `admin_base_url`; no redirects | `plugin::admin_base_url_must_be_loopback`, `client::redirects_are_not_followed` |
| AC-55 | Dotted topics; compliance refused in subscribe | `types::topic_parses_and_maps_to_graphql_enum` (`customer.tags_added`), `client::subscribe_webhook_refuses_compliance_and_bad_topics` |
| AC-56 | `on_install`, `install_url` | `oauth::callback_runs_the_install_handler_after_the_token_is_stored`, `a_failing_install_handler_is_500_and_keeps_the_token`, `plugin::install_url_points_at_the_install_route`; smoke (303 to `install_url`) |
| AC-57 | `after_install_path` query and fragment; new env vars | `oauth::after_install_location_keeps_an_existing_query`, `config::after_install_path_allows_a_query_but_not_a_fragment`, `env_sets_after_install_path_and_retries` |
| AC-58 | `#[non_exhaustive]` with constructors | Source attributes; constructors used by tests (`RetryPolicy::new`, `ShopToken::with_refresh`, `WebhookContext::new`) |

## Review round 2

| AC | Criterion | Evidence |
|---|---|---|
| AC-59 | A late owner cannot change a newer claim | `delivery::a_stale_owner_cannot_change_a_newer_claim` |
| AC-60 | One lock per shop, never pruned | `plugin::an_uninstall_keeps_the_per_shop_lock_entry` |
| AC-61 | Refresh 401 terminal, 403 keeps, replica pair used | `plugin::a_refused_refresh_deletes_the_token`, `a_refresh_403_keeps_the_token`, `a_refused_refresh_uses_and_keeps_a_pair_another_replica_stored` |
| AC-62 | No public secret getters | `compile_fail` doctests on `ShopifyConfig` (`secrets`, `access_token`) and `SecretSet` (`current`) |
| AC-63 | `InstallContext::new` | `plugin::install_context_new_fills_the_state_from_the_handle` |
| AC-64 | Docs match code | Round 2 docs review; README, CHANGELOG, CLAUDE.md, ADR, module docs updated |

## TDD record

- RED: 155 tests against `todo!()` stubs. 141 failed, 14 passed (the 14
  check declarations only: error mapping, defaults, endpoints).
- GREEN: all passed with the first implementation.
- Now: 195 unit tests, 3 doc examples, 3 `compile_fail` doctests. Ten
  repeated runs: all green.

## Not covered by tooling here

- Verus proofs: Verus is not installed in this environment. Property tests
  (proptest) cover the invariants instead: shop-domain anchoring, HMAC
  sign/verify, claim capacity, and claim exclusion.
