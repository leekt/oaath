//! The owner-transaction request (`owner-transaction.ts`): one exact plain
//! transaction an OAAth signer's own wallet sends from the portal. The relay
//! captures it exactly as the TS owner does; it never signs, sends, or reads a
//! chain.

use serde_json::{Value, json};

use crate::capture::{
    MAX_SAFE_INTEGER_U64, ZERO_ADDRESS, capture_address, exact_record, field, is_lower_hex_bytes,
    safe_integer,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure};

pub const OWNER_TRANSACTION_REQUEST_VERSION: &str = "oaath.owner-transaction-request/v1";
const CODE: ErrorCode = ErrorCode::SigningRequestInvalid;
/// Init code may be as large as EIP-3860 allows, twice over.
const MAX_DATA_BYTES: usize = 96 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerTransactionRequest {
    pub chain_id: u64,
    /// The signer's own wallet address, lowercase.
    pub from: String,
    /// `None` for a contract creation.
    pub to: Option<String>,
    /// Canonical decimal uint256 wei.
    pub value: String,
    pub data: String,
}

impl OwnerTransactionRequest {
    pub fn to_json(&self) -> Value {
        json!({
            "version": OWNER_TRANSACTION_REQUEST_VERSION,
            "chainId": self.chain_id,
            "from": self.from,
            "to": self.to,
            "value": self.value,
            "data": self.data,
        })
    }
}

fn nonzero_address(value: &Value) -> Option<String> {
    capture_address(value).filter(|address| address != ZERO_ADDRESS)
}

/// Captures one exact owner-transaction request.
pub fn parse_owner_transaction_request(value: &Value) -> ProtocolResult<OwnerTransactionRequest> {
    let record = exact_record(
        value,
        &["version", "chainId", "from", "to", "value", "data"],
    )
    .or_fail(CODE)?;
    ensure(
        field(record, "version") == OWNER_TRANSACTION_REQUEST_VERSION,
        CODE,
    )?;
    let chain_id = safe_integer(field(record, "chainId"), 1, MAX_SAFE_INTEGER_U64).or_fail(CODE)?;
    let from = nonzero_address(field(record, "from")).or_fail(CODE)?;
    let to = match field(record, "to") {
        Value::Null => None,
        target => Some(nonzero_address(target).or_fail(CODE)?),
    };
    let value = crate::capture::decimal_uint256(field(record, "value"))
        .or_fail(CODE)?
        .to_owned();
    let data = field(record, "data")
        .as_str()
        .filter(|text| is_lower_hex_bytes(text) && text.len() <= 2 + MAX_DATA_BYTES * 2)
        .or_fail(CODE)?
        .to_owned();
    // A creation needs init code.
    ensure(to.is_some() || data != "0x", CODE)?;
    Ok(OwnerTransactionRequest {
        chain_id,
        from,
        to,
        value,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({
            "version": OWNER_TRANSACTION_REQUEST_VERSION,
            "chainId": 8453,
            "from": format!("0x{}", "11".repeat(20)),
            "to": format!("0x{}", "22".repeat(20)),
            "value": "1000000000000000000",
            "data": "0xabcdef01",
        })
    }

    #[test]
    fn captures_a_call_with_value_and_a_creation_exactly() {
        let call = request();
        assert_eq!(
            parse_owner_transaction_request(&call).unwrap().to_json(),
            call
        );
        let mut creation = request();
        creation["to"] = Value::Null;
        creation["data"] = json!("0x6080");
        assert_eq!(
            parse_owner_transaction_request(&creation)
                .unwrap()
                .to_json(),
            creation
        );
    }

    #[test]
    fn refuses_anything_inexact() {
        let mutations: [(&str, Value); 9] = [
            ("version", json!("oaath.owner-transaction-request/v2")),
            ("chainId", json!(0)),
            ("from", json!(ZERO_ADDRESS)),
            ("to", json!(ZERO_ADDRESS)),
            ("value", json!("01")),
            ("value", json!("-1")),
            ("data", json!("0xABCD")),
            ("data", json!("0x123")),
            ("data", json!(1)),
        ];
        for (key, value) in mutations {
            let mut changed = request();
            changed[key] = value;
            assert!(parse_owner_transaction_request(&changed).is_err(), "{key}");
        }
        let mut empty_creation = request();
        empty_creation["to"] = Value::Null;
        empty_creation["data"] = json!("0x");
        assert!(parse_owner_transaction_request(&empty_creation).is_err());
        let mut extra = request();
        extra["extra"] = json!(1);
        assert!(parse_owner_transaction_request(&extra).is_err());
    }
}
