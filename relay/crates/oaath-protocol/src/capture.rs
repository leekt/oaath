//! Exact capture over parsed JSON with the JavaScript semantics the
//! TypeScript owner applies after `JSON.parse`.
//!
//! - records have exactly the listed keys (duplicate JSON keys: last wins,
//!   matching both `JSON.parse` and `serde_json`);
//! - string lengths count UTF-16 code units;
//! - numbers are JavaScript doubles: `1.0` and `1e3` are integers, `-0` is
//!   distinct, and anything above 2^53 - 1 is not a safe integer.
//!
//! Build every `Value` these parsers see with [`parse_json`]: plain
//! `serde_json` reads the integer token `-0` as `0`, which JavaScript does not.

use std::borrow::Cow;

use alloy_primitives::U256;
use serde_json::{Map, Value};

pub type Record = Map<String, Value>;

/// `JSON.parse` for the protocol: as `serde_json`, except that the integer
/// token `-0` keeps its sign (it is read as the equal JavaScript `-0.0`).
pub fn parse_json(text: &str) -> serde_json::Result<Value> {
    serde_json::from_str(&preserve_negative_zero(text))
}

fn preserve_negative_zero(text: &str) -> Cow<'_, str> {
    if !text.contains("-0") {
        return Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut rewritten = String::with_capacity(text.len() + 8);
    let (mut copied, mut in_string, mut escaped) = (0, false, false);
    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
        } else if *byte == b'"' {
            in_string = true;
        } else if *byte == b'-'
            && bytes.get(index + 1) == Some(&b'0')
            && !matches!(bytes.get(index + 2), Some(b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            rewritten.push_str(&text[copied..index + 2]);
            rewritten.push_str(".0");
            copied = index + 2;
        }
    }
    rewritten.push_str(&text[copied..]);
    Cow::Owned(rewritten)
}

/// A plain JSON object.
pub fn capture_record(value: &Value) -> Option<&Record> {
    value.as_object()
}

/// Whether `record` has exactly `keys`, in any order.
pub fn has_exact_keys(record: &Record, keys: &[&str]) -> bool {
    record.len() == keys.len() && record.keys().all(|key| keys.contains(&key.as_str()))
}

/// A plain JSON object with exactly `keys`.
pub fn exact_record<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Record> {
    capture_record(value).filter(|record| has_exact_keys(record, keys))
}

/// A JSON array. Parsed JSON arrays are always dense.
pub fn capture_dense_array(value: &Value) -> Option<&Vec<Value>> {
    value.as_array()
}

/// `record[key]`, with an absent key read as JavaScript `undefined`.
pub(crate) fn field<'a>(record: &'a Record, key: &str) -> &'a Value {
    static UNDEFINED: Value = Value::Null;
    // Callers capture exact records first, so a key is never absent here; the
    // fallback only keeps the read total.
    record.get(key).unwrap_or(&UNDEFINED)
}

/// Length in UTF-16 code units, as JavaScript `String.prototype.length`.
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The JavaScript double a JSON number parses to.
fn js_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        _ => None,
    }
}

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// `Number.isSafeInteger(value) && !Object.is(value, -0)` within bounds.
pub fn safe_integer(value: &Value, minimum: u64, maximum: u64) -> Option<u64> {
    let number = js_number(value)?;
    if number.fract() != 0.0
        || number.abs() > MAX_SAFE_INTEGER
        || (number == 0.0 && number.is_sign_negative())
        || number < minimum as f64
        || number > maximum as f64
    {
        return None;
    }
    Some(number as u64)
}

/// `typeof value === "number" && Number.isSafeInteger(value)`, where `-0`
/// compares equal to zero.
pub(crate) fn loose_safe_integer(value: &Value) -> Option<i64> {
    let number = js_number(value)?;
    if number.fract() != 0.0 || number.abs() > MAX_SAFE_INTEGER {
        return None;
    }
    Some(number as i64)
}

pub const MAX_SAFE_INTEGER_U64: u64 = 9_007_199_254_740_991;
pub const MAX_UINT48: u64 = (1 << 48) - 1;

/// ECMAScript `WhiteSpace` and `LineTerminator`, the set `String.prototype.trim` removes.
fn is_js_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

/// `value === value.trim()`.
pub(crate) fn is_js_trimmed(text: &str) -> bool {
    !text.starts_with(is_js_whitespace) && !text.ends_with(is_js_whitespace)
}

/// A string of 1 through `maximum` UTF-16 units equal to its JavaScript trim.
pub(crate) fn canonical_bounded_string(value: &Value, maximum: usize) -> Option<&str> {
    let text = value.as_str()?;
    let length = utf16_len(text);
    (length >= 1 && length <= maximum && is_js_trimmed(text)).then_some(text)
}

/// A string of 1 through `maximum` UTF-16 units.
pub(crate) fn bounded_text(value: &Value, maximum: usize) -> Option<&str> {
    let text = value.as_str()?;
    let length = utf16_len(text);
    (length >= 1 && length <= maximum).then_some(text)
}

/// `^0x[0-9a-f]{2*bytes}$`.
pub(crate) fn is_lower_hex(text: &str, bytes: usize) -> bool {
    text.len() == 2 + bytes * 2 && is_lower_hex_bytes(text)
}

/// `^0x(?:[0-9a-f]{2})*$`.
pub(crate) fn is_lower_hex_bytes(text: &str) -> bool {
    text.strip_prefix("0x").is_some_and(|digits| {
        digits.len() % 2 == 0
            && digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// `^0x[0-9a-f]{64}$`.
pub(crate) fn lower_hash(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| is_lower_hex(text, 32))
}

/// `^0x[0-9a-f]{40}$`.
pub(crate) fn lower_address(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| is_lower_hex(text, 20))
}

pub(crate) const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
pub(crate) const ZERO_HASH: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

/// `^(?:0|[1-9][0-9]*)$` with at most `max_digits` digits.
pub(crate) fn is_canonical_decimal(text: &str, max_digits: usize) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max_digits
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes[0] != b'0' || bytes.len() == 1)
}

/// A canonical decimal string at most 2^256 - 1.
pub(crate) fn decimal_uint256(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    (is_canonical_decimal(text, 78) && U256::from_str_radix(text, 10).is_ok()).then_some(text)
}

/// Decodes canonical `0x` hex already validated by a capture.
pub(crate) fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(&text[2..]).expect("captured hex is canonical")
}
