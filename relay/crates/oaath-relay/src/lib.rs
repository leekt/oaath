//! OAAth authorization relay: the Rust port of `packages/server`'s relay core.
//!
//! The HTTP wire (paths, methods, statuses, JSON bodies, headers, and the
//! `{"error":{"code":...}}` envelope) is identical to the TypeScript relay so
//! the SDK, phone, and extension clients work unchanged.

pub mod account_import;
pub mod authentication;
pub mod authority;
pub mod authorization;
pub mod bootstrap;
pub mod clock;
pub mod config;
pub mod display;
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
pub mod session;
pub mod store;

pub use error::{RelayErrorCode, RelayResult};
pub use handler::{Relay, RelayOptions};
