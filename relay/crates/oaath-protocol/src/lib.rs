//! Rust port of the `@oaath/protocol` contracts the relay consumes.
//!
//! `@oaath/protocol` (TypeScript) remains the wire owner for the SDK, phone,
//! and extension. Every rule here is pinned to it by the generated fixtures in
//! `relay/fixtures/protocol`, which `scripts/export-protocol-fixtures.mjs`
//! writes by evaluating the TypeScript sources.
//!
//! Every parser takes JSON parsed with [`capture::parse_json`] (or, where the
//! relay holds stored text, the text itself) and returns one immutable
//! captured value or a [`ProtocolError`] carrying the TypeScript error code.

pub mod capture;
mod error;
pub mod grant_policy;
pub mod grant_reference;
pub mod identity;
pub mod ids;
pub mod kernel_install;
pub mod owner_signing;
pub mod permission;
pub mod pkce;
pub mod scope;
pub mod service_bootstrap;
pub mod signing_request;
mod web_url;

pub use error::{ErrorCode, ProtocolError, ProtocolResult};
