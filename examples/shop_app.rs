//! A Shopify app on Autumn: webhooks, OAuth install, and Admin API calls.
//!
//! ## Setup
//!
//! 1. Create an app in the Shopify Dev Dashboard. Copy the client id.
//! 2. Write `autumn.toml`:
//!
//!    ```toml
//!    [shopify]
//!    api_key = "<client id>"
//!    app_url = "https://<your-host>"
//!    scopes = ["read_orders", "read_products"]
//!    ```
//!
//! 3. Export the client secret:
//!
//!    ```sh
//!    export SHOPIFY_API_SECRET="<client secret>"
//!    ```
//!
//! 4. Set the app redirect URL to `https://<your-host>/shopify/auth/callback`
//!    and the webhook URL to `https://<your-host>/shopify/webhooks`.
//! 5. Run `cargo run --example shop_app`, then open
//!    `https://<your-host>/shopify/auth?shop=<store>.myshopify.com`.
//!
//! This example stores no customer data, so the compliance handlers only
//! log. A real app must send or delete the data it keeps.

use autumn_plugin_shopify::{
    ErrorKind, InstallContext, ShopDomain, Shopify, ShopifyPlugin, Topic, WebhookContext,
};
use autumn_web::prelude::*;
use autumn_web::reexports::axum::response::{IntoResponse, Redirect, Response};

/// Log each new order. Slow work belongs in a background job: Shopify
/// waits only 5 seconds.
async fn order_created(ctx: WebhookContext) -> AutumnResult<()> {
    let order: serde_json::Value = ctx.json().map_err(|err| err.to_autumn_error())?;
    tracing::info!(shop = %ctx.shop, order = %order["id"], "order created");
    Ok(())
}

/// Compliance: send the stored data of one customer to the merchant.
async fn customer_data_request(ctx: WebhookContext) -> AutumnResult<()> {
    tracing::info!(shop = %ctx.shop, "customer data request received");
    Ok(())
}

/// Compliance: delete the stored data of one customer.
async fn customer_redact(ctx: WebhookContext) -> AutumnResult<()> {
    tracing::info!(shop = %ctx.shop, "customer redact received");
    Ok(())
}

/// Compliance: delete all stored data of one shop. The plugin already
/// deleted the shop token.
async fn shop_redact(ctx: WebhookContext) -> AutumnResult<()> {
    tracing::info!(shop = %ctx.shop, "shop redact received");
    Ok(())
}

/// After an install: subscribe to `app/uninstalled`. Errors give 500.
async fn installed(ctx: InstallContext) -> AutumnResult<()> {
    let client = ctx
        .shopify
        .client_for(&ctx.shop)
        .await
        .map_err(|err| err.to_autumn_error())?;
    let app_url = ctx
        .shopify
        .runtime()
        .config()
        .app_url
        .clone()
        .unwrap_or_default();
    let url = format!("{}/shopify/webhooks", app_url.trim_end_matches('/'));
    client
        .subscribe_webhook(Topic::APP_UNINSTALLED, &url)
        .await
        .map_err(|err| err.to_autumn_error())?;
    Ok(())
}

/// The page after an install. Nothing signs the `shop` value. Do not open
/// a session from it.
#[get("/")]
#[public]
async fn home() -> &'static str {
    "Installed."
}

/// Show the name of an installed shop.
///
/// DEMO ONLY: this route has no authentication, so anyone can read the
/// name of any installed shop. Guard it with `#[secured]` in a real app.
#[get("/shops/{shop}")]
#[public]
async fn shop_name(shopify: Shopify, Path(shop): Path<String>) -> AutumnResult<Response> {
    let shop = ShopDomain::parse(&shop).map_err(|err| err.to_autumn_error())?;
    let client = match shopify.client_for(&shop).await {
        Ok(client) => client,
        Err(err) if matches!(err.kind(), ErrorKind::NotInstalled | ErrorKind::Reauthorize) => {
            return Ok(Redirect::to(&Shopify::install_url(&shop)).into_response());
        }
        Err(err) => return Err(err.to_autumn_error()),
    };
    let info = client
        .shop_info()
        .await
        .map_err(|err| err.to_autumn_error())?;
    Ok(info.name.into_response())
}

#[autumn_web::main]
async fn main() {
    Box::pin(
        autumn_web::app()
            .routes(routes![home, shop_name])
            .plugin(
                ShopifyPlugin::new()
                    .on_install(installed)
                    .webhook("orders/create", order_created)
                    .webhook(Topic::CUSTOMERS_DATA_REQUEST, customer_data_request)
                    .webhook(Topic::CUSTOMERS_REDACT, customer_redact)
                    .webhook(Topic::SHOP_REDACT, shop_redact),
            )
            .run(),
    )
    .await;
}
