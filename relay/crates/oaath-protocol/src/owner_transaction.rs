//! The owner-transaction request (`owner-transaction.ts`): one exact plain
//! transaction an OAAth signer's own wallet sends from the portal. The relay
//! captures it exactly as the TS owner does; it never signs, sends, or reads a
//! chain.

use serde_json::{Value, json};

use crate::capture::{
    MAX_SAFE_INTEGER_U64, ZERO_ADDRESS, capture_address, capture_record, exact_record, field,
    has_exact_keys, is_js_trimmed, is_lower_hex_bytes, safe_integer, utf16_len,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure};

pub const OWNER_TRANSACTION_REQUEST_VERSION: &str = "oaath.owner-transaction-request/v1";
const CODE: ErrorCode = ErrorCode::SigningRequestInvalid;
/// Init code may be as large as EIP-3860 allows, twice over.
const MAX_DATA_BYTES: usize = 96 * 1024;
const MAX_NAME: usize = 64;
const MAX_SYMBOL: usize = 12;
const MAX_URL: usize = 256;
const MAX_URLS: usize = 4;
const KEYS: [&str; 6] = ["version", "chainId", "from", "to", "value", "data"];

/// EIP-3085 metadata to add a chain the sender's wallet may not know yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerTransactionChain {
    pub name: String,
    pub currency_name: String,
    pub currency_symbol: String,
    /// Canonical `https` URLs, one to four.
    pub rpc_urls: Vec<String>,
    pub block_explorer_urls: Option<Vec<String>>,
}

impl OwnerTransactionChain {
    fn to_json(&self) -> Value {
        let mut chain = json!({
            "name": self.name,
            "nativeCurrency": {
                "name": self.currency_name,
                "symbol": self.currency_symbol,
                "decimals": 18,
            },
            "rpcUrls": self.rpc_urls,
        });
        if let Some(urls) = &self.block_explorer_urls {
            chain["blockExplorerUrls"] = json!(urls);
        }
        chain
    }
}

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
    pub chain: Option<OwnerTransactionChain>,
}

impl OwnerTransactionRequest {
    pub fn to_json(&self) -> Value {
        let mut request = json!({
            "version": OWNER_TRANSACTION_REQUEST_VERSION,
            "chainId": self.chain_id,
            "from": self.from,
            "to": self.to,
            "value": self.value,
            "data": self.data,
        });
        if let Some(chain) = &self.chain {
            request["chain"] = chain.to_json();
        }
        request
    }
}

fn text(value: &Value, maximum: usize) -> Option<String> {
    value
        .as_str()
        .filter(|text| (1..=maximum).contains(&utf16_len(text)) && is_js_trimmed(text))
        .map(str::to_owned)
}

/// Canonical WHATWG `https` URL with no credentials, query, or fragment.
fn https_url(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    if utf16_len(text) > MAX_URL || text.contains(['?', '#']) {
        return None;
    }
    let url = url::Url::parse(text).ok()?;
    (url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.as_str() == text)
        .then(|| text.to_owned())
}

fn urls(value: &Value) -> Option<Vec<String>> {
    let entries = value.as_array()?;
    if !(1..=MAX_URLS).contains(&entries.len()) {
        return None;
    }
    entries.iter().map(https_url).collect()
}

fn capture_chain(value: &Value) -> Option<OwnerTransactionChain> {
    let record = capture_record(value)?;
    let explorer = record.contains_key("blockExplorerUrls");
    let keys: &[&str] = if explorer {
        &["name", "nativeCurrency", "rpcUrls", "blockExplorerUrls"]
    } else {
        &["name", "nativeCurrency", "rpcUrls"]
    };
    if !has_exact_keys(record, keys) {
        return None;
    }
    let currency = exact_record(
        field(record, "nativeCurrency"),
        &["name", "symbol", "decimals"],
    )?;
    safe_integer(field(currency, "decimals"), 18, 18)?;
    Some(OwnerTransactionChain {
        name: text(field(record, "name"), MAX_NAME)?,
        currency_name: text(field(currency, "name"), MAX_NAME)?,
        currency_symbol: text(field(currency, "symbol"), MAX_SYMBOL)?,
        rpc_urls: urls(field(record, "rpcUrls"))?,
        block_explorer_urls: if explorer {
            Some(urls(field(record, "blockExplorerUrls"))?)
        } else {
            None
        },
    })
}

fn nonzero_address(value: &Value) -> Option<String> {
    capture_address(value).filter(|address| address != ZERO_ADDRESS)
}

/// Captures one exact owner-transaction request.
pub fn parse_owner_transaction_request(value: &Value) -> ProtocolResult<OwnerTransactionRequest> {
    let record = capture_record(value).or_fail(CODE)?;
    let has_chain = record.contains_key("chain");
    ensure(
        record.len() == KEYS.len() + usize::from(has_chain)
            && record
                .keys()
                .all(|key| key == "chain" || KEYS.contains(&key.as_str())),
        CODE,
    )?;
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
    let chain = if has_chain {
        Some(capture_chain(field(record, "chain")).or_fail(CODE)?)
    } else {
        None
    };
    Ok(OwnerTransactionRequest {
        chain_id,
        from,
        to,
        value,
        data,
        chain,
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

    fn chain() -> Value {
        json!({
            "name": "Example Chain",
            "nativeCurrency": { "name": "Ether", "symbol": "ETH", "decimals": 18 },
            "rpcUrls": ["https://rpc.example.org/v1"],
            "blockExplorerUrls": ["https://explorer.example.org/"],
        })
    }

    #[test]
    fn captures_chain_metadata_exactly() {
        let mut with_chain = request();
        with_chain["chain"] = chain();
        assert_eq!(
            parse_owner_transaction_request(&with_chain)
                .unwrap()
                .to_json(),
            with_chain
        );
        // Canonical key order: the stored PAR text must match the TS owner's JSON.
        assert_eq!(
            parse_owner_transaction_request(&with_chain)
                .unwrap()
                .to_json()
                .to_string(),
            with_chain.to_string()
        );
        with_chain["chain"]
            .as_object_mut()
            .unwrap()
            .remove("blockExplorerUrls");
        assert_eq!(
            parse_owner_transaction_request(&with_chain)
                .unwrap()
                .to_json(),
            with_chain
        );
    }

    #[test]
    fn refuses_unsafe_or_inexact_chain_metadata() {
        let mutations: [(&str, Value); 13] = [
            ("rpcUrls", json!(["http://rpc.example.org/"])),
            ("rpcUrls", json!(["https://user:pass@rpc.example.org/"])),
            ("rpcUrls", json!(["https://rpc.example.org/?key=1"])),
            ("rpcUrls", json!(["https://rpc.example.org/#x"])),
            ("rpcUrls", json!(["https://rpc.example.org"])),
            ("rpcUrls", json!([])),
            ("rpcUrls", json!(vec!["https://rpc.example.org/"; 5])),
            ("blockExplorerUrls", json!(["http://explorer.example.org/"])),
            ("blockExplorerUrls", json!([])),
            ("name", json!("")),
            ("name", json!(" padded")),
            (
                "nativeCurrency",
                json!({ "name": "Ether", "symbol": "ETH", "decimals": 6 }),
            ),
            ("extra", json!(1)),
        ];
        for (key, value) in mutations {
            let mut changed = request();
            changed["chain"] = chain();
            changed["chain"][key] = value;
            assert!(parse_owner_transaction_request(&changed).is_err(), "{key}");
        }
        let mut null_chain = request();
        null_chain["chain"] = Value::Null;
        assert!(parse_owner_transaction_request(&null_chain).is_err());
    }
}
