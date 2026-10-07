use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};

pub const VERSION: &str = "oaath.dca-terms/v1";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Terms {
    pub version: String,
    pub plan_id: String,
    pub account: String,
    pub chain_id: u64,
    pub sell_token: String,
    pub buy_token: String,
    pub amount_in: String,
    pub total_input_cap: String,
    pub start_at: u64,
    pub interval_seconds: u32,
    pub grace_seconds: u32,
    pub max_runs: u32,
    pub end_at: u64,
    pub recipient: String,
    pub router: String,
    pub pool_fee: u32,
    pub sell_feed: String,
    pub buy_feed: String,
    pub max_price_age_seconds: u32,
    pub max_slippage_bps: u16,
}
pub fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(bytes)))
}
pub fn address(s: &str) -> Result<String, &'static str> {
    if s.len() != 42
        || !s.starts_with("0x")
        || !s[2..].bytes().all(|c| c.is_ascii_hexdigit())
        || s[2..].bytes().all(|c| c == b'0')
    {
        return Err("address_invalid");
    }
    Ok(s.to_lowercase())
}
pub fn word(s: &str) -> Result<[u8; 32], &'static str> {
    let b = if let Some(v) = s.strip_prefix("0x") {
        hex::decode(v).map_err(|_| "terms_invalid")?
    } else {
        s.parse::<BigUint>()
            .map_err(|_| "terms_invalid")?
            .to_bytes_be()
    };
    if b.len() > 32 {
        return Err("terms_invalid");
    }
    let mut out = [0; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}
impl Terms {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != VERSION {
            return Err("dca_version_unsupported");
        }
        for a in [
            &self.account,
            &self.sell_token,
            &self.buy_token,
            &self.recipient,
            &self.router,
            &self.sell_feed,
            &self.buy_feed,
        ] {
            if address(a)? != *a {
                return Err("terms_invalid");
            }
        }
        if self.plan_id.len() != 66
            || !self.plan_id.starts_with("0x")
            || self.plan_id[2..].bytes().any(|c| !c.is_ascii_hexdigit())
            || word(&self.plan_id)? == [0; 32]
            || self.chain_id == 0
            || self.chain_id > 9_007_199_254_740_991
            || self.account != self.recipient
            || self.sell_token == self.buy_token
            || self.interval_seconds != 86400
            || self.grace_seconds == 0
            || self.grace_seconds > 86400
            || self.max_runs == 0
            || self.max_runs > 365
            || self.max_slippage_bps > 1000
            || self.pool_fee == 0
            || self.pool_fee >= 1_000_000
            || self.max_price_age_seconds == 0
            || self.max_price_age_seconds > 86400
        {
            return Err("terms_invalid");
        }
        let end = self
            .start_at
            .checked_add(u64::from(self.max_runs - 1) * 86400)
            .and_then(|v| v.checked_add(u64::from(self.grace_seconds)))
            .ok_or("terms_invalid")?;
        if self.start_at == 0 || self.end_at != end || self.end_at > 9_007_199_254_740_991 {
            return Err("terms_invalid");
        }
        for s in [&self.amount_in, &self.total_input_cap] {
            if s.is_empty()
                || s.len() > 78
                || s.starts_with('0')
                || !s.bytes().all(|c| c.is_ascii_digit())
            {
                return Err("terms_invalid");
            }
            word(s)?;
        }
        if self.amount_in.parse::<BigUint>().unwrap() * self.max_runs
            != self.total_input_cap.parse::<BigUint>().unwrap()
        {
            return Err("terms_invalid");
        }
        Ok(())
    }
    pub fn commitment(&self) -> Result<String, &'static str> {
        self.validate()?;
        let v = serde_json::to_value(self).unwrap();
        let names = [
            "planId",
            "account",
            "chainId",
            "sellToken",
            "buyToken",
            "amountIn",
            "totalInputCap",
            "startAt",
            "intervalSeconds",
            "graceSeconds",
            "maxRuns",
            "endAt",
            "recipient",
            "router",
            "poolFee",
            "sellFeed",
            "buyFeed",
            "maxPriceAgeSeconds",
            "maxSlippageBps",
        ];
        let mut bytes = Keccak256::digest(VERSION.as_bytes()).to_vec();
        for name in names {
            let val = &v[name];
            bytes.extend(word(&match val {
                Value::String(s) => s.clone(),
                _ => val.to_string(),
            })?);
        }
        Ok(hash(&bytes))
    }
    pub fn slot_digest(&self, slot: u32) -> Result<String, &'static str> {
        if slot >= self.max_runs {
            return Err("slot_invalid");
        }
        let mut b = Keccak256::digest(b"oaath.dca-slot/v1").to_vec();
        b.extend(word(&self.commitment()?)?);
        b.extend(word(&slot.to_string())?);
        Ok(hash(&b))
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Asset {
    pub token: String,
    pub amount: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub account: String,
    pub chain_id: u64,
    pub sell: Asset,
    pub buy: Asset,
    pub interval_seconds: u32,
    pub max_runs: u32,
    pub max_slippage_bps: u16,
    pub start_at: Option<u64>,
    pub idempotency_key: String,
}
pub fn base_units(input: &str) -> Result<String, &'static str> {
    let parts: Vec<_> = input.split('.').collect();
    if parts.len() > 2
        || parts[0].is_empty()
        || !parts[0].bytes().all(|c| c.is_ascii_digit())
        || (parts[0].len() > 1 && parts[0].starts_with('0'))
        || parts[0].len() > 60
    {
        return Err("amount_invalid");
    }
    let fraction = parts.get(1).copied().unwrap_or("");
    if fraction.len() > 6
        || !fraction.bytes().all(|c| c.is_ascii_digit())
        || (parts.len() == 2 && fraction.is_empty())
    {
        return Err("amount_invalid");
    }
    let digits = format!("{}{:0<6}", parts[0], fraction);
    let value = digits.parse::<BigUint>().map_err(|_| "amount_invalid")?;
    if value == BigUint::from(0u8) || value.bits() > 256 {
        return Err("amount_invalid");
    }
    Ok(value.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn money_is_exact() {
        assert_eq!(base_units("25").unwrap(), "25000000");
        assert_eq!(base_units("0.000001").unwrap(), "1");
        for x in ["0", "-1", "1e6", "01", "1.0000001", "1.", ".1"] {
            assert!(base_units(x).is_err());
        }
    }
}
