//! OAAth relay: the OAuth 2.0 / OpenID Connect issuer and the portal's API.
//!
//! Failures leave as the `{"error":{"code":...}}` envelope on `/portal/*` and
//! as RFC 6749 bodies with an `error_code` on `/oauth/*`.

pub mod account_import;
pub mod authentication;
pub mod authority;
pub mod authorization;
pub mod bundler;
pub mod chain;
pub mod clock;
pub mod error;
pub mod grant;
pub mod handler;
pub mod kms;
pub mod link;
pub mod member_grant;
pub mod oauth;
pub mod policy;
pub mod portal;
pub mod records;
pub mod registry;
pub mod revocation;
pub mod session;
pub mod store;

pub use error::{RelayErrorCode, RelayResult};
pub use handler::{Relay, RelayOptions};
