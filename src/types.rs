//! Validated domain types: [`ShopDomain`], [`Topic`], [`ApiVersion`].
//!
//! Each type checks its value once, at parse time. Code that holds one of
//! these types holds a valid value.

use std::fmt;

use crate::error::{Error, Result};

/// The Admin API version the plugin uses when the config sets none.
pub const DEFAULT_API_VERSION: &str = "2026-10";

/// The longest shop domain accepted (a DNS name limit).
const MAX_SHOP_LEN: usize = 253;

/// A shop's permanent `*.myshopify.com` domain.
///
/// [`ShopDomain::parse`] accepts only `^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$`
/// and stores the value in lowercase. It does not trim whitespace.
///
/// The plugin builds every outbound shop URL from this type, so a hostile
/// host never receives a secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShopDomain(String);

impl ShopDomain {
    /// Parse and validate a shop domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] when the value does not match the
    /// anchored myshopify pattern.
    pub fn parse(value: &str) -> Result<Self> {
        let lower = value.to_ascii_lowercase();
        let label = lower.strip_suffix(".myshopify.com").unwrap_or_default();
        let valid = lower.len() <= MAX_SHOP_LEN
            && label
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !valid {
            return Err(Error::InvalidRequest(
                "shop must be a *.myshopify.com domain".to_owned(),
            ));
        }
        Ok(Self(lower))
    }

    /// The domain as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShopDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ShopDomain {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A webhook topic, for example `orders/create` or `customer.tags_added`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic(String);

impl Topic {
    /// `app/uninstalled`: the merchant removed the app.
    pub const APP_UNINSTALLED: &'static str = "app/uninstalled";
    /// `customers/data_request`: compliance, send customer data.
    pub const CUSTOMERS_DATA_REQUEST: &'static str = "customers/data_request";
    /// `customers/redact`: compliance, delete customer data.
    pub const CUSTOMERS_REDACT: &'static str = "customers/redact";
    /// `shop/redact`: compliance, delete shop data.
    pub const SHOP_REDACT: &'static str = "shop/redact";
    /// The three mandatory compliance topics.
    pub const COMPLIANCE: &'static [&'static str] = &[
        Self::CUSTOMERS_DATA_REQUEST,
        Self::CUSTOMERS_REDACT,
        Self::SHOP_REDACT,
    ];

    /// Parse and validate a topic.
    ///
    /// A topic has two or more segments joined by `/` or `.`. Each segment
    /// is one or more of `a-z`, `0-9`, `_`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] when the topic is malformed.
    pub fn parse(value: &str) -> Result<Self> {
        let segments: Vec<&str> = value.split(['/', '.']).collect();
        let valid = segments.len() >= 2
            && segments.iter().all(|segment| {
                !segment.is_empty()
                    && segment
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            });
        if !valid {
            return Err(Error::InvalidRequest(format!(
                "webhook topic {value:?} must look like \"orders/create\""
            )));
        }
        Ok(Self(value.to_owned()))
    }

    /// The topic as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The GraphQL `WebhookSubscriptionTopic` enum value:
    /// `orders/create` becomes `ORDERS_CREATE`, and `customer.tags_added`
    /// becomes `CUSTOMER_TAGS_ADDED`.
    #[must_use]
    pub fn graphql_enum(&self) -> String {
        self.0.replace(['/', '.'], "_").to_ascii_uppercase()
    }

    /// True for the three mandatory compliance topics.
    #[must_use]
    pub fn is_compliance(&self) -> bool {
        Self::COMPLIANCE.contains(&self.0.as_str())
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An Admin API version: `YYYY-01`, `YYYY-04`, `YYYY-07`, `YYYY-10`, or
/// `unstable`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiVersion(String);

impl ApiVersion {
    /// Parse and validate an API version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the version is malformed.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let quarterly = match value.as_bytes() {
            [y1, y2, y3, y4, b'-', m1, m2] => {
                [y1, y2, y3, y4].iter().all(|b| b.is_ascii_digit())
                    && matches!([m1, m2], [b'0', b'1' | b'4' | b'7'] | [b'1', b'0'])
            }
            _ => false,
        };
        if quarterly || value == "unstable" {
            Ok(Self(value.to_owned()))
        } else {
            Err(Error::Config(format!(
                "api_version {value:?} must be YYYY-01, YYYY-04, YYYY-07, YYYY-10, or unstable"
            )))
        }
    }

    /// The version as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ApiVersion {
    fn default() -> Self {
        Self(DEFAULT_API_VERSION.to_owned())
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
