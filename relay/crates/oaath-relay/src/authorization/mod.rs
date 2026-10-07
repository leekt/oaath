//! The authorization record state machine the OAuth and portal flows share:
//! one-time codes and artifacts, capability invalidation, and PKCE.

pub mod artifact;
pub mod challenge;
pub mod code;
pub mod invalidation;
