//! Grant policy capture, hashing, and attenuation (`grant-policy.ts`).

use std::collections::HashMap;

use alloy_primitives::{Address, B256, FixedBytes, U256, keccak256};
use alloy_sol_types::SolValue;
use serde_json::{Value, json};

use crate::capture::{
    MAX_SAFE_INTEGER_U64, MAX_UINT48, ZERO_ADDRESS, capture_dense_array, decimal_uint256,
    exact_record, field, hex_bytes, is_lower_hex, safe_integer,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure};
use crate::identity::{address_of, b256_of, hex_hash};

pub const GRANT_POLICY_VERSION: &str = "oaath.grant-policy/v2";
pub const GRANT_POLICY_HASH_DOMAIN: &str = "@oaath/protocol:grant-policy";
pub const GRANT_POLICY_CALLS_HASH_DOMAIN: &str = "@oaath/protocol:grant-policy-calls";

const ZERO_SELECTOR: &str = "0x00000000";
const MAX_ARGUMENT_INDEX: u64 = MAX_SAFE_INTEGER_U64 / 32;

/// Equality on one zero-based 32-byte ABI word after the selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPolicyArgumentEquality {
    pub index: u64,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPolicyCall {
    pub target: String,
    pub selector: String,
    /// Canonical decimal uint256 string.
    pub value_limit: String,
    pub argument_equals: Vec<GrantPolicyArgumentEquality>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantPolicyOperationLimit {
    pub count: u64,
    /// `None` is the only non-resetting (lifetime) representation.
    pub interval_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPolicy {
    pub calls: Vec<GrantPolicyCall>,
    /// Inclusive Unix seconds.
    pub valid_after: u64,
    /// Inclusive Unix seconds, or `None` as the only indefinite representation.
    pub valid_until: Option<u64>,
    pub per_chain_operation_limit: GrantPolicyOperationLimit,
}

fn uint48(value: &Value, minimum: u64, code: ErrorCode) -> ProtocolResult<u64> {
    safe_integer(value, minimum, MAX_UINT48).or_fail(code)
}

fn nullable_uint48(value: &Value, minimum: u64, code: ErrorCode) -> ProtocolResult<Option<u64>> {
    if value.is_null() {
        Ok(None)
    } else {
        uint48(value, minimum, code).map(Some)
    }
}

fn capture_argument_equality(
    value: &Value,
    code: ErrorCode,
) -> ProtocolResult<GrantPolicyArgumentEquality> {
    let record = exact_record(value, &["index", "value"]).or_fail(code)?;
    let word = field(record, "value")
        .as_str()
        .filter(|text| is_lower_hex(text, 32));
    Ok(GrantPolicyArgumentEquality {
        index: safe_integer(field(record, "index"), 0, MAX_ARGUMENT_INDEX).or_fail(code)?,
        value: word.or_fail(code)?.to_owned(),
    })
}

fn capture_call(value: &Value, code: ErrorCode) -> ProtocolResult<GrantPolicyCall> {
    let record = exact_record(
        value,
        &["target", "selector", "valueLimit", "argumentEquals"],
    )
    .or_fail(code)?;
    let argument_equals = capture_dense_array(field(record, "argumentEquals"))
        .or_fail(code)?
        .iter()
        .map(|entry| capture_argument_equality(entry, code))
        .collect::<ProtocolResult<Vec<_>>>()?;
    ensure(
        argument_equals
            .windows(2)
            .all(|pair| pair[0].index < pair[1].index),
        code,
    )?;
    let target = crate::capture::capture_address(field(record, "target"))
        .filter(|text| text != ZERO_ADDRESS);
    let selector = field(record, "selector")
        .as_str()
        .filter(|text| is_lower_hex(text, 4) && *text != ZERO_SELECTOR);
    Ok(GrantPolicyCall {
        target: target.or_fail(code)?.to_owned(),
        selector: selector.or_fail(code)?.to_owned(),
        value_limit: decimal_uint256(field(record, "valueLimit"))
            .or_fail(code)?
            .to_owned(),
        argument_equals,
    })
}

/// `target:selector`, the unique sorted key of one permitted call.
fn call_key(call: &GrantPolicyCall) -> String {
    format!("{}:{}", call.target, call.selector)
}

fn capture_calls(value: &Value, code: ErrorCode) -> ProtocolResult<Vec<GrantPolicyCall>> {
    let entries = capture_dense_array(value).or_fail(code)?;
    ensure(!entries.is_empty(), code)?;
    let calls = entries
        .iter()
        .map(|entry| capture_call(entry, code))
        .collect::<ProtocolResult<Vec<_>>>()?;
    // Keys are ASCII, so byte order is JavaScript string order.
    ensure(
        calls
            .windows(2)
            .all(|pair| call_key(&pair[0]) < call_key(&pair[1])),
        code,
    )?;
    Ok(calls)
}

pub(crate) fn capture_policy(value: &Value, code: ErrorCode) -> ProtocolResult<GrantPolicy> {
    let record = exact_record(
        value,
        &[
            "version",
            "calls",
            "validAfter",
            "validUntil",
            "perChainOperationLimit",
        ],
    )
    .or_fail(code)?;
    ensure(field(record, "version") == GRANT_POLICY_VERSION, code)?;
    let calls = capture_calls(field(record, "calls"), code)?;
    let valid_after = uint48(field(record, "validAfter"), 0, code)?;
    let valid_until = nullable_uint48(field(record, "validUntil"), 1, code)?;
    ensure(valid_until.is_none_or(|until| valid_after <= until), code)?;
    let limit = exact_record(
        field(record, "perChainOperationLimit"),
        &["count", "intervalSeconds"],
    )
    .or_fail(code)?;
    Ok(GrantPolicy {
        calls,
        valid_after,
        valid_until,
        per_chain_operation_limit: GrantPolicyOperationLimit {
            count: uint48(field(limit, "count"), 1, code)?,
            interval_seconds: nullable_uint48(field(limit, "intervalSeconds"), 1, code)?,
        },
    })
}

pub fn parse_grant_policy(value: &Value) -> ProtocolResult<GrantPolicy> {
    capture_policy(value, ErrorCode::GrantPolicyInvalid)
}

type EncodedArgument = (U256, B256);
type EncodedCall = (Address, FixedBytes<4>, U256, Vec<EncodedArgument>);

fn encode_calls(calls: &[GrantPolicyCall]) -> Vec<EncodedCall> {
    calls
        .iter()
        .map(|call| {
            (
                address_of(&call.target),
                FixedBytes::<4>::from_slice(&hex_bytes(&call.selector)),
                U256::from_str_radix(&call.value_limit, 10).expect("captured uint256"),
                call.argument_equals
                    .iter()
                    .map(|argument| (U256::from(argument.index), b256_of(&argument.value)))
                    .collect(),
            )
        })
        .collect()
}

impl GrantPolicy {
    /// `hashGrantPolicy` over this captured policy.
    pub fn hash(&self) -> B256 {
        keccak256(
            (
                GRANT_POLICY_HASH_DOMAIN.to_owned(),
                GRANT_POLICY_VERSION.to_owned(),
                encode_calls(&self.calls),
                U256::from(self.valid_after),
                self.valid_until.is_some(),
                U256::from(self.valid_until.unwrap_or(0)),
                U256::from(self.per_chain_operation_limit.count),
                // Zero is unambiguous as "no window": a present interval is at least one second.
                U256::from(self.per_chain_operation_limit.interval_seconds.unwrap_or(0)),
            )
                .abi_encode_params(),
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": GRANT_POLICY_VERSION,
            "calls": self.calls.iter().map(GrantPolicyCall::to_json).collect::<Vec<_>>(),
            "validAfter": self.valid_after,
            "validUntil": self.valid_until,
            "perChainOperationLimit": {
                "count": self.per_chain_operation_limit.count,
                "intervalSeconds": self.per_chain_operation_limit.interval_seconds,
            },
        })
    }
}

impl GrantPolicyCall {
    pub fn to_json(&self) -> Value {
        json!({
            "target": self.target,
            "selector": self.selector,
            "valueLimit": self.value_limit,
            "argumentEquals": self.argument_equals.iter().map(|argument| json!({
                "index": argument.index,
                "value": argument.value,
            })).collect::<Vec<_>>(),
        })
    }
}

pub fn hash_grant_policy(value: &Value) -> ProtocolResult<String> {
    Ok(hex_hash(parse_grant_policy(value)?.hash()))
}

/// Digest of one exact call set in canonical policy order, independent of the
/// policy's time window and rate limit.
pub fn hash_grant_policy_calls(value: &Value) -> ProtocolResult<String> {
    Ok(hash_captured_calls(&capture_calls(
        value,
        ErrorCode::GrantPolicyInvalid,
    )?))
}

/// `hashGrantPolicyCalls` over calls already captured in canonical order.
pub fn hash_captured_calls(calls: &[GrantPolicyCall]) -> String {
    hex_hash(keccak256(
        (
            GRANT_POLICY_CALLS_HASH_DOMAIN.to_owned(),
            GRANT_POLICY_VERSION.to_owned(),
            encode_calls(calls),
        )
            .abi_encode_params(),
    ))
}

fn uint256_of(text: &str) -> U256 {
    U256::from_str_radix(text, 10).expect("captured uint256")
}

fn call_attenuates(requested: &GrantPolicyCall, approved: &GrantPolicyCall) -> bool {
    if uint256_of(&approved.value_limit) > uint256_of(&requested.value_limit) {
        return false;
    }
    // Later duplicates win, as in a JavaScript Map built from entries.
    let approved_arguments: HashMap<u64, &str> = approved
        .argument_equals
        .iter()
        .map(|argument| (argument.index, argument.value.as_str()))
        .collect();
    requested
        .argument_equals
        .iter()
        .all(|argument| approved_arguments.get(&argument.index) == Some(&argument.value.as_str()))
}

/// Whether `approved` is no broader than `requested` on every axis.
pub fn is_captured_policy_attenuation(requested: &GrantPolicy, approved: &GrantPolicy) -> bool {
    let requested_limit = requested.per_chain_operation_limit;
    let approved_limit = approved.per_chain_operation_limit;
    if approved.valid_after < requested.valid_after
        || requested.valid_until.is_some_and(|requested_until| {
            approved.valid_until.is_none_or(|approved_until| approved_until > requested_until)
        })
        || approved_limit.count > requested_limit.count
        // The window is kept exactly: approval may only lower the count.
        || approved_limit.interval_seconds != requested_limit.interval_seconds
    {
        return false;
    }
    let requested_calls: HashMap<String, &GrantPolicyCall> = requested
        .calls
        .iter()
        .map(|call| (call_key(call), call))
        .collect();
    approved.calls.iter().all(|call| {
        requested_calls
            .get(&call_key(call))
            .is_some_and(|requested| call_attenuates(requested, call))
    })
}

pub fn is_grant_policy_attenuation(requested: &Value, approved: &Value) -> ProtocolResult<bool> {
    let code = ErrorCode::GrantPolicyAttenuationInputInvalid;
    let requested = capture_policy(requested, code)?;
    let approved = capture_policy(approved, code)?;
    Ok(is_captured_policy_attenuation(&requested, &approved))
}
