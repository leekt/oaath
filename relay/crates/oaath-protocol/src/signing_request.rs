//! Owner-signing requests and canonical EIP-712 typed data
//! (`signing-request.ts`, hashing as cetane `hashTypedData`).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use alloy_primitives::{B256, I256, U256, keccak256};
use alloy_sol_types::SolValue;
use serde_json::{Map, Value, json};

use crate::capture::{
    ZERO_ADDRESS, capture_dense_array, capture_record, exact_record, field, has_exact_keys,
    hex_bytes, is_canonical_decimal, is_lower_hex_bytes, lower_address, lower_hash, utf16_len,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure, fail};
use crate::identity::{
    OwnerCredentialProfile, address_of, b256_of, capture_owner_credential, hex_hash,
};

pub const OWNER_SIGNING_REQUEST_VERSION: &str = "oaath.owner-signing-request/v1";
pub const OWNER_SIGNING_REQUEST_HASH_DOMAIN: &str = "@oaath/protocol:owner-signing-request";

const CODE: ErrorCode = ErrorCode::SigningRequestInvalid;
const RESERVED_RECORD_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];
const MAX_TYPES: usize = 64;
const MAX_FIELDS: usize = 64;
const MAX_IDENTIFIER_LENGTH: usize = 64;
const MAX_DEPTH: usize = 16;
const MAX_ARRAY_LENGTH: usize = 256;
const MAX_SCALAR_BYTES: usize = 16 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024;
const MAX_TOTAL_VALUES: usize = 4_096;
const DOMAIN_FIELDS: [(&str, &str); 5] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eip712SigningPurpose {
    Permit,
    Permit2,
    Application,
    KernelEnable,
}

impl Eip712SigningPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Permit2 => "permit2",
            Self::Application => "application",
            Self::KernelEnable => "kernel-enable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip712Field {
    pub name: String,
    pub r#type: String,
}

/// Captured EIP-712 typed data. `domain` and `message` are canonical JSON
/// trees of strings, booleans, arrays, and objects in schema field order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEip712TypedData {
    /// Struct schemas keyed in sorted name order.
    pub types: BTreeMap<String, Vec<Eip712Field>>,
    pub primary_type: String,
    pub domain: Value,
    pub message: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSigningRequestSigner {
    pub account: String,
    pub owner_credential: OwnerCredentialProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSigningReplayFacts {
    pub nonce: Option<String>,
    pub deadline: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip712OwnerSigningRequest {
    pub purpose: Eip712SigningPurpose,
    pub signer: OwnerSigningRequestSigner,
    pub typed_data: CanonicalEip712TypedData,
    pub expected_digest: String,
    pub replay: OwnerSigningReplayFacts,
}

/// A raw digest is representable only as reject-only evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDigestOwnerSigningRequest {
    pub digest: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerSigningRequest {
    Eip712(Box<Eip712OwnerSigningRequest>),
    RawDigest(RawDigestOwnerSigningRequest),
}

/// Array suffixes from innermost to outermost; `None` is dynamic.
struct ParsedType<'a> {
    base: &'a str,
    dimensions: Vec<Option<usize>>,
}

#[derive(Default)]
struct Budget {
    values: usize,
    bytes: usize,
}

impl Budget {
    fn consume_bytes(&mut self, text: &str, maximum: usize) -> ProtocolResult<()> {
        let bytes = text.len();
        ensure(
            bytes <= maximum && self.bytes + bytes <= MAX_TOTAL_BYTES,
            CODE,
        )?;
        self.bytes += bytes;
        Ok(())
    }

    fn consume_value(&mut self) -> ProtocolResult<()> {
        self.values += 1;
        ensure(self.values <= MAX_TOTAL_VALUES, CODE)
    }
}

/// `^[A-Za-z_][A-Za-z0-9_]*$`.
fn is_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn identifier_text(text: &str) -> ProtocolResult<&str> {
    ensure(
        utf16_len(text) <= MAX_IDENTIFIER_LENGTH
            && is_identifier(text)
            && !RESERVED_RECORD_KEYS.contains(&text),
        CODE,
    )?;
    Ok(text)
}

fn identifier(value: &Value) -> ProtocolResult<&str> {
    identifier_text(value.as_str().or_fail(CODE)?)
}

fn canonical_number(text: &str) -> bool {
    is_canonical_decimal(text, usize::MAX)
}

fn parse_type(text: &str) -> ProtocolResult<ParsedType<'_>> {
    ensure(utf16_len(text) <= MAX_IDENTIFIER_LENGTH * 2, CODE)?;
    let (base, mut rest) = text.split_at(text.find('[').unwrap_or(text.len()));
    ensure(is_identifier(base), CODE)?;
    let mut dimensions = Vec::new();
    while !rest.is_empty() {
        let inner = rest.strip_prefix('[').or_fail(CODE)?;
        let close = inner.find(|c: char| !c.is_ascii_digit()).or_fail(CODE)?;
        ensure(inner.as_bytes()[close] == b']', CODE)?;
        let length = &inner[..close];
        if length.is_empty() {
            dimensions.push(None);
        } else {
            ensure(canonical_number(length) && length != "0", CODE)?;
            let parsed = length
                .parse::<usize>()
                .ok()
                .filter(|value| *value <= MAX_ARRAY_LENGTH);
            dimensions.push(Some(parsed.or_fail(CODE)?));
        }
        rest = &inner[close + 1..];
    }
    ensure(base != "uint" && base != "int", CODE)?;
    if let Some(width) = base
        .strip_prefix("uint")
        .or_else(|| base.strip_prefix("int"))
    {
        ensure(canonical_number(width), CODE)?;
        let width = width.parse::<usize>().unwrap_or(usize::MAX);
        ensure((8..=256).contains(&width) && width % 8 == 0, CODE)?;
    } else if let Some(width) = base.strip_prefix("bytes").filter(|width| !width.is_empty()) {
        ensure(canonical_number(width), CODE)?;
        let width = width.parse::<usize>().unwrap_or(usize::MAX);
        ensure((1..=32).contains(&width), CODE)?;
    }
    Ok(ParsedType { base, dimensions })
}

fn is_builtin(base: &str) -> bool {
    if matches!(base, "address" | "bool" | "string" | "bytes") {
        return true;
    }
    let width = |digits: &str| {
        !digits.is_empty() && !digits.starts_with('0') && digits.bytes().all(|b| b.is_ascii_digit())
    };
    if let Some(digits) = base.strip_prefix("bytes") {
        return width(digits) && digits.parse::<u32>().is_ok_and(|n| (1..=32).contains(&n));
    }
    if let Some(digits) = base
        .strip_prefix("uint")
        .or_else(|| base.strip_prefix("int"))
    {
        return width(digits)
            && digits
                .parse::<u32>()
                .is_ok_and(|n| (8..=256).contains(&n) && n % 8 == 0);
    }
    false
}

type Types = BTreeMap<String, Vec<Eip712Field>>;

fn capture_types(value: &Value, budget: &mut Budget) -> ProtocolResult<Types> {
    let record = capture_record(value).or_fail(CODE)?;
    // Struct names are ASCII once validated, so byte order is JavaScript sort order.
    let names: BTreeSet<&String> = record.keys().collect();
    ensure(
        (2..=MAX_TYPES).contains(&names.len()) && record.contains_key("EIP712Domain"),
        CODE,
    )?;
    let mut types = Types::new();
    for name in names {
        identifier_text(name)?;
        budget.consume_bytes(name, MAX_SCALAR_BYTES)?;
        ensure(!is_builtin(name), CODE)?;
        let entries = capture_dense_array(&record[name]).or_fail(CODE)?;
        ensure(entries.len() <= MAX_FIELDS, CODE)?;
        let mut field_names = HashSet::new();
        let mut fields = Vec::with_capacity(entries.len());
        for entry in entries {
            let captured = exact_record(entry, &["name", "type"]).or_fail(CODE)?;
            let field_name = identifier(field(captured, "name"))?;
            ensure(field_names.insert(field_name), CODE)?;
            let r#type = field(captured, "type").as_str().or_fail(CODE)?;
            parse_type(r#type)?;
            budget.consume_bytes(field_name, MAX_SCALAR_BYTES)?;
            budget.consume_bytes(r#type, MAX_SCALAR_BYTES)?;
            fields.push(Eip712Field {
                name: field_name.to_owned(),
                r#type: r#type.to_owned(),
            });
        }
        types.insert(name.clone(), fields);
    }

    let domain_fields = &types["EIP712Domain"];
    ensure(!domain_fields.is_empty(), CODE)?;
    let mut previous = None;
    for domain_field in domain_fields {
        let index = DOMAIN_FIELDS
            .iter()
            .position(|(name, r#type)| *name == domain_field.name && *r#type == domain_field.r#type)
            .or_fail(CODE)?;
        ensure(previous.is_none_or(|previous| index > previous), CODE)?;
        previous = Some(index);
    }

    for fields in types.values() {
        for declared in fields {
            let base = parse_type(&declared.r#type)?.base;
            ensure(is_builtin(base) || types.contains_key(base), CODE)?;
        }
    }
    Ok(types)
}

fn capture_scalar(value: &Value, base: &str, budget: &mut Budget) -> ProtocolResult<Value> {
    budget.consume_value()?;
    if base == "bool" {
        return Ok(Value::Bool(value.as_bool().or_fail(CODE)?));
    }
    if base == "address" {
        let address = lower_address(value).or_fail(CODE)?;
        budget.consume_bytes(address, MAX_SCALAR_BYTES)?;
        return Ok(Value::String(address.to_owned()));
    }
    if base == "string" {
        let text = value.as_str().or_fail(CODE)?;
        budget.consume_bytes(text, MAX_SCALAR_BYTES)?;
        return Ok(Value::String(text.to_owned()));
    }
    if let Some(width) = base.strip_prefix("bytes") {
        let text = value
            .as_str()
            .filter(|text| is_lower_hex_bytes(text))
            .or_fail(CODE)?;
        let byte_length = (text.len() - 2) / 2;
        let expected = if width.is_empty() {
            None
        } else {
            width.parse::<usize>().ok()
        };
        ensure(
            expected.is_none_or(|expected| byte_length == expected)
                && byte_length <= MAX_SCALAR_BYTES,
            CODE,
        )?;
        budget.consume_bytes(text, 2 + MAX_SCALAR_BYTES * 2)?;
        return Ok(Value::String(text.to_owned()));
    }
    let (signed, width) = match (base.strip_prefix("uint"), base.strip_prefix("int")) {
        (Some(width), _) => (false, width),
        (_, Some(width)) => (true, width),
        _ => return fail(CODE),
    };
    let width: usize = width.parse().ok().or_fail(CODE)?;
    let text = value.as_str().or_fail(CODE)?;
    let digits = if signed {
        text.strip_prefix('-').filter(|d| *d != "0").unwrap_or(text)
    } else {
        text
    };
    ensure(canonical_number(digits) && utf16_len(text) <= 79, CODE)?;
    let magnitude = U256::from_str_radix(digits, 10).ok();
    let in_range = match (signed, magnitude) {
        (_, None) => false,
        (false, Some(magnitude)) => width == 256 || magnitude < U256::from(1) << width,
        (true, Some(magnitude)) => {
            let bound = U256::from(1) << (width - 1);
            if text.starts_with('-') {
                magnitude <= bound
            } else {
                magnitude < bound
            }
        }
    };
    ensure(in_range, CODE)?;
    budget.consume_bytes(text, MAX_SCALAR_BYTES)?;
    Ok(Value::String(text.to_owned()))
}

fn capture_value(
    value: &Value,
    base: &str,
    dimensions: &[Option<usize>],
    types: &Types,
    depth: usize,
    budget: &mut Budget,
) -> ProtocolResult<Value> {
    ensure(depth <= MAX_DEPTH, CODE)?;
    if let Some((outermost, inner)) = dimensions.split_last() {
        budget.consume_value()?;
        let entries = capture_dense_array(value).or_fail(CODE)?;
        ensure(
            entries.len() <= MAX_ARRAY_LENGTH
                && outermost.is_none_or(|length| entries.len() == length),
            CODE,
        )?;
        return entries
            .iter()
            .map(|entry| capture_value(entry, base, inner, types, depth + 1, budget))
            .collect::<ProtocolResult<Vec<_>>>()
            .map(Value::Array);
    }
    let Some(fields) = types.get(base) else {
        return capture_scalar(value, base, budget);
    };
    budget.consume_value()?;
    let names: Vec<&str> = fields
        .iter()
        .map(|declared| declared.name.as_str())
        .collect();
    let record = exact_record(value, &names).or_fail(CODE)?;
    let mut captured = Map::new();
    for declared in fields {
        let parsed = parse_type(&declared.r#type)?;
        let entry = capture_value(
            field(record, &declared.name),
            parsed.base,
            &parsed.dimensions,
            types,
            depth + 1,
            budget,
        )?;
        captured.insert(declared.name.clone(), entry);
    }
    Ok(Value::Object(captured))
}

pub(crate) fn capture_typed_data(value: &Value) -> ProtocolResult<CanonicalEip712TypedData> {
    let mut budget = Budget::default();
    let record =
        exact_record(value, &["types", "primaryType", "domain", "message"]).or_fail(CODE)?;
    let types = capture_types(field(record, "types"), &mut budget)?;
    let primary_type = identifier(field(record, "primaryType"))?;
    ensure(
        primary_type != "EIP712Domain" && types.contains_key(primary_type),
        CODE,
    )?;
    let mut reachable: HashSet<&str> = HashSet::from(["EIP712Domain"]);
    let mut pending = vec![primary_type];
    while let Some(name) = pending.pop() {
        if !reachable.insert(name) {
            continue;
        }
        for declared in types.get(name).into_iter().flatten() {
            let dependency = parse_type(&declared.r#type)?.base;
            if !is_builtin(dependency) && !reachable.contains(dependency) {
                pending.push(dependency);
            }
        }
    }
    ensure(reachable.len() == types.len(), CODE)?;
    let domain = capture_value(
        field(record, "domain"),
        "EIP712Domain",
        &[],
        &types,
        0,
        &mut budget,
    )?;
    let message = capture_value(
        field(record, "message"),
        primary_type,
        &[],
        &types,
        0,
        &mut budget,
    )?;
    Ok(CanonicalEip712TypedData {
        primary_type: primary_type.to_owned(),
        types,
        domain,
        message,
    })
}

pub fn parse_canonical_eip712_typed_data(
    value: &Value,
) -> ProtocolResult<CanonicalEip712TypedData> {
    capture_typed_data(value)
}

fn decimal_uint(value: &Value) -> ProtocolResult<String> {
    let text = value.as_str().filter(|text| {
        canonical_number(text) && text.len() <= 78 && U256::from_str_radix(text, 10).is_ok()
    });
    Ok(text.or_fail(CODE)?.to_owned())
}

fn nullable_decimal_uint(value: &Value) -> ProtocolResult<Option<String>> {
    if value.is_null() {
        Ok(None)
    } else {
        decimal_uint(value).map(Some)
    }
}

fn bounded_reason(value: &Value) -> ProtocolResult<String> {
    let text = value
        .as_str()
        .filter(|text| (1..=256).contains(&utf16_len(text)))
        .filter(|text| !text.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f));
    Ok(text.or_fail(CODE)?.to_owned())
}

pub(crate) fn capture_owner_signing_request(value: &Value) -> ProtocolResult<OwnerSigningRequest> {
    let record = capture_record(value).or_fail(CODE)?;
    if record.get("kind").and_then(Value::as_str) == Some("raw-digest") {
        ensure(
            has_exact_keys(record, &["version", "kind", "digest", "reason", "decision"]),
            CODE,
        )?;
        ensure(
            field(record, "version") == OWNER_SIGNING_REQUEST_VERSION
                && field(record, "decision") == "reject-only",
            CODE,
        )?;
        return Ok(OwnerSigningRequest::RawDigest(
            RawDigestOwnerSigningRequest {
                digest: lower_hash(field(record, "digest"))
                    .or_fail(CODE)?
                    .to_owned(),
                reason: bounded_reason(field(record, "reason"))?,
            },
        ));
    }
    ensure(
        has_exact_keys(
            record,
            &[
                "version",
                "kind",
                "purpose",
                "signer",
                "typedData",
                "expectedDigest",
                "replay",
            ],
        ),
        CODE,
    )?;
    ensure(
        field(record, "version") == OWNER_SIGNING_REQUEST_VERSION
            && field(record, "kind") == "eip712",
        CODE,
    )?;
    let purpose = match field(record, "purpose").as_str() {
        Some("permit") => Eip712SigningPurpose::Permit,
        Some("permit2") => Eip712SigningPurpose::Permit2,
        Some("application") => Eip712SigningPurpose::Application,
        Some("kernel-enable") => Eip712SigningPurpose::KernelEnable,
        _ => return fail(CODE),
    };
    let signer =
        exact_record(field(record, "signer"), &["account", "ownerCredential"]).or_fail(CODE)?;
    let account = lower_address(field(signer, "account")).filter(|text| *text != ZERO_ADDRESS);
    let replay = exact_record(field(record, "replay"), &["nonce", "deadline"]).or_fail(CODE)?;
    Ok(OwnerSigningRequest::Eip712(Box::new(
        Eip712OwnerSigningRequest {
            purpose,
            signer: OwnerSigningRequestSigner {
                account: account.or_fail(CODE)?.to_owned(),
                owner_credential: capture_owner_credential(field(signer, "ownerCredential"), CODE)?,
            },
            typed_data: capture_typed_data(field(record, "typedData"))?,
            expected_digest: lower_hash(field(record, "expectedDigest"))
                .or_fail(CODE)?
                .to_owned(),
            replay: OwnerSigningReplayFacts {
                nonce: nullable_decimal_uint(field(replay, "nonce"))?,
                deadline: nullable_decimal_uint(field(replay, "deadline"))?,
            },
        },
    )))
}

pub fn parse_owner_signing_request(value: &Value) -> ProtocolResult<OwnerSigningRequest> {
    capture_owner_signing_request(value)
}

fn word(value: U256) -> B256 {
    B256::from(value.to_be_bytes::<32>())
}

/// Splits the outermost array suffix, as cetane's `/^(.*)\[([0-9]*)\]$/`.
fn split_outer_array(r#type: &str) -> Option<&str> {
    let inner = r#type.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    inner[open + 1..]
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| &inner[..open])
}

fn base_type(r#type: &str) -> &str {
    let mut base = r#type;
    while let Some(inner) = split_outer_array(base) {
        base = inner;
    }
    base
}

impl CanonicalEip712TypedData {
    fn type_hash(&self, name: &str) -> B256 {
        let mut dependencies = BTreeSet::new();
        let mut pending = vec![name];
        while let Some(current) = pending.pop() {
            if !dependencies.insert(current) {
                continue;
            }
            for declared in &self.types[current] {
                let base = base_type(&declared.r#type);
                if !is_builtin(base) {
                    pending.push(base);
                }
            }
        }
        dependencies.remove(name);
        let mut encoded = String::new();
        for struct_name in std::iter::once(name).chain(dependencies) {
            let fields: Vec<String> = self.types[struct_name]
                .iter()
                .map(|declared| format!("{} {}", declared.r#type, declared.name))
                .collect();
            encoded.push_str(&format!("{struct_name}({})", fields.join(",")));
        }
        keccak256(encoded.as_bytes())
    }

    fn encode(&self, r#type: &str, value: &Value) -> B256 {
        if let Some(inner) = split_outer_array(r#type) {
            let entries = value.as_array().expect("captured array");
            let mut encoded = Vec::with_capacity(entries.len() * 32);
            for entry in entries {
                encoded.extend_from_slice(self.encode(inner, entry).as_slice());
            }
            return keccak256(encoded);
        }
        if let Some(fields) = self.types.get(r#type) {
            let mut encoded = self.type_hash(r#type).to_vec();
            for declared in fields {
                encoded.extend_from_slice(
                    self.encode(&declared.r#type, &value[&declared.name])
                        .as_slice(),
                );
            }
            return keccak256(encoded);
        }
        let text = || value.as_str().expect("captured scalar");
        match r#type {
            "string" => keccak256(text().as_bytes()),
            "bytes" => keccak256(hex_bytes(text())),
            "bool" => word(U256::from(value.as_bool().expect("captured bool") as u8)),
            "address" => B256::left_padding_from(&hex_bytes(text())),
            _ if r#type.starts_with("bytes") => B256::right_padding_from(&hex_bytes(text())),
            _ if r#type.starts_with("uint") => {
                word(U256::from_str_radix(text(), 10).expect("captured uint"))
            }
            _ => word(I256::from_dec_str(text()).expect("captured int").into_raw()),
        }
    }

    /// The EIP-712 digest cetane `hashTypedData` computes for this value.
    pub fn hash(&self) -> ProtocolResult<B256> {
        // cetane refuses struct names spelled as the bare integer aliases.
        ensure(
            !self.types.contains_key("uint") && !self.types.contains_key("int"),
            CODE,
        )?;
        let mut encoded = vec![0x19, 0x01];
        encoded.extend_from_slice(self.encode("EIP712Domain", &self.domain).as_slice());
        encoded.extend_from_slice(self.encode(&self.primary_type, &self.message).as_slice());
        Ok(keccak256(encoded))
    }

    pub fn to_json(&self) -> Value {
        let types: Map<String, Value> = self
            .types
            .iter()
            .map(|(name, fields)| {
                let fields = fields
                    .iter()
                    .map(|declared| json!({"name": declared.name, "type": declared.r#type}))
                    .collect();
                (name.clone(), Value::Array(fields))
            })
            .collect();
        json!({
            "types": types,
            "primaryType": self.primary_type,
            "domain": self.domain,
            "message": self.message,
        })
    }
}

pub fn hash_canonical_eip712_typed_data(value: &Value) -> ProtocolResult<String> {
    Ok(hex_hash(capture_typed_data(value)?.hash()?))
}

impl OwnerSigningRequest {
    /// `hashOwnerSigningRequest` over this captured request.
    pub fn hash(&self) -> ProtocolResult<B256> {
        let domain = OWNER_SIGNING_REQUEST_HASH_DOMAIN.to_owned();
        let version = OWNER_SIGNING_REQUEST_VERSION.to_owned();
        Ok(keccak256(match self {
            Self::RawDigest(request) => (
                domain,
                version,
                "raw-digest".to_owned(),
                b256_of(&request.digest),
                request.reason.clone(),
                "reject-only".to_owned(),
            )
                .abi_encode_params(),
            Self::Eip712(request) => {
                let nonce = request.replay.nonce.as_deref();
                let deadline = request.replay.deadline.as_deref();
                let uint = |text: Option<&str>| {
                    U256::from_str_radix(text.unwrap_or("0"), 10).expect("captured uint256")
                };
                (
                    domain,
                    version,
                    "eip712".to_owned(),
                    request.purpose.as_str().to_owned(),
                    address_of(&request.signer.account),
                    request.signer.owner_credential.hash(),
                    request.typed_data.hash()?,
                    b256_of(&request.expected_digest),
                    nonce.is_some(),
                    uint(nonce),
                    deadline.is_some(),
                    uint(deadline),
                )
                    .abi_encode_params()
            }
        }))
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::RawDigest(request) => json!({
                "version": OWNER_SIGNING_REQUEST_VERSION,
                "kind": "raw-digest",
                "digest": request.digest,
                "reason": request.reason,
                "decision": "reject-only",
            }),
            Self::Eip712(request) => json!({
                "version": OWNER_SIGNING_REQUEST_VERSION,
                "kind": "eip712",
                "purpose": request.purpose.as_str(),
                "signer": {
                    "account": request.signer.account,
                    "ownerCredential": request.signer.owner_credential.to_json(),
                },
                "typedData": request.typed_data.to_json(),
                "expectedDigest": request.expected_digest,
                "replay": {"nonce": request.replay.nonce, "deadline": request.replay.deadline},
            }),
        }
    }
}

pub fn hash_owner_signing_request(value: &Value) -> ProtocolResult<String> {
    Ok(hex_hash(parse_owner_signing_request(value)?.hash()?))
}
