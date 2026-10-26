//! Test helpers: a scripted local HTTP stub that stands in for Shopify.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

/// One scripted answer.
#[derive(Debug, Clone)]
pub struct StubResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl StubResponse {
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string(),
        }
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_owned(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// One recorded request.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Recorded {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("recorded body is json")
    }

    pub fn form(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(&self.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

#[derive(Clone, Default)]
struct Shared {
    script: Arc<Mutex<VecDeque<StubResponse>>>,
    seen: Arc<Mutex<Vec<Recorded>>>,
}

/// A running stub server.
pub struct Stub {
    pub base_url: String,
    shared: Shared,
}

impl Stub {
    /// Start a stub that answers with `script` in order. Extra requests get
    /// a 599 answer, which fails the test that made them.
    pub async fn start(script: Vec<StubResponse>) -> Self {
        let shared = Shared {
            script: Arc::new(Mutex::new(script.into())),
            seen: Arc::default(),
        };
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("stub binds");
        let addr = listener.local_addr().expect("stub has an addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            shared,
        }
    }

    /// The requests seen so far.
    pub fn requests(&self) -> Vec<Recorded> {
        self.shared.seen.lock().expect("lock").clone()
    }
}

async fn handle(
    State(shared): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    shared.seen.lock().expect("lock").push(Recorded {
        method,
        path: uri
            .path_and_query()
            .map_or_else(|| uri.path().to_owned(), ToString::to_string),
        headers,
        body,
    });
    let next = shared.script.lock().expect("lock").pop_front();
    let Some(answer) = next else {
        return (
            StatusCode::from_u16(599).expect("valid"),
            "stub script is empty",
        )
            .into_response();
    };
    let mut response = Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        response = response.header(name.as_str(), value.as_str());
    }
    response
        .body(axum::body::Body::from(answer.body))
        .expect("stub response builds")
}

// ── Runtime and app helpers ──────────────────────────────────────────

use autumn_web::AppState;
use autumn_web::entropy::SeededEntropy;
use autumn_web::test::{TestApp, TestClient};
use autumn_web::time::FixedClock;

use crate::config::ShopifyConfig;
use crate::plugin::ShopifyRuntime;

/// The test client secret.
pub const SECRET: &str = "hush";
/// The test shop.
pub const SHOP: &str = "my-store.myshopify.com";
/// A fixed test time (Unix seconds, October 2026).
pub const NOW: i64 = 1_793_000_000;

/// An OAuth-enabled TOML document.
pub const OAUTH_TOML: &str = r#"
[shopify]
api_key = "client-id"
app_url = "https://app.example.com"
scopes = ["read_orders", "write_products"]
after_install_path = "/welcome"
"#;

/// An env lookup over fixed pairs.
pub fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let map: std::collections::HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

/// A config from `toml` with the test secret plus `extra` env pairs.
pub fn config(toml: Option<&str>, extra: &[(&str, &str)]) -> ShopifyConfig {
    let mut pairs = vec![("SHOPIFY_API_SECRET", SECRET)];
    pairs.extend_from_slice(extra);
    ShopifyConfig::from_sources(toml, env(&pairs)).expect("test config loads")
}

/// A test state at [`NOW`] with seeded entropy and `runtime` installed.
pub fn state(runtime: Option<ShopifyRuntime>) -> AppState {
    let now = autumn_web::reexports::chrono::DateTime::from_timestamp(NOW, 0).expect("valid time");
    let state = AppState::for_test()
        .with_clock(Arc::new(FixedClock::at(now)))
        .with_entropy(Arc::new(SeededEntropy::new(7)));
    if let Some(runtime) = runtime {
        state.insert_extension(runtime);
    }
    state
}

/// A test client over the plugin routes.
pub fn app(state: &AppState) -> TestClient {
    let (router, _) = crate::plugin::mount();
    let router = axum::Router::new()
        .nest("/shopify", router)
        .with_state(state.clone());
    TestApp::from_router(router, state.clone())
}
