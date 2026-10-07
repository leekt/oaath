//! The relay's ES256 id_token key and its public JWKS.
//!
//! One P-256 key from a PKCS#8 PEM file, identified by a configured `kid` or,
//! by default, its RFC 7638 JWK thumbprint.
//! `jsonwebtoken` signs; the JWKS is derived from the same key, so the
//! published key can never drift from the signing key. Rotation is deferred.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{RelayErrorCode, RelayResult};
use crate::records::canonical_str;

pub struct IdTokenKey {
    kid: String,
    encoding: EncodingKey,
    jwks: Value,
}

impl IdTokenKey {
    /// Parses a PKCS#8 PEM P-256 private key. Without a `kid`, the key's RFC
    /// 7638 thumbprint names it. Failures never echo the key.
    pub fn from_pkcs8_pem(kid: Option<&str>, pem: &str) -> Option<Self> {
        let secret = SecretKey::from_pkcs8_pem(pem).ok()?;
        let point = secret.public_key().to_encoded_point(false);
        let encoding = EncodingKey::from_ec_pem(pem.as_bytes()).ok()?;
        let x = URL_SAFE_NO_PAD.encode(point.x()?);
        let y = URL_SAFE_NO_PAD.encode(point.y()?);
        // RFC 7638: the required members in lexicographic order, no spaces.
        let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#).as_bytes(),
        ));
        let kid = kid.map_or(thumbprint, str::to_owned);
        canonical_str(&kid, RelayErrorCode::Internal).ok()?;
        let jwks = json!({ "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
        }] });
        Some(Self {
            kid,
            encoding,
            jwks,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn jwks(&self) -> &Value {
        &self.jwks
    }

    pub fn sign(&self, claims: &impl Serialize) -> RelayResult<String> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &self.encoding).map_err(|_| RelayErrorCode::Internal)
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::{JwkSet, ThumbprintHash};
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    use super::IdTokenKey;

    #[test]
    fn names_an_unlabelled_key_by_its_rfc_7638_thumbprint() {
        let pem = p256::SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        let key = IdTokenKey::from_pkcs8_pem(None, &pem).unwrap();
        let jwks: JwkSet = serde_json::from_value(key.jwks().clone()).unwrap();
        assert_eq!(key.kid(), jwks.keys[0].thumbprint(ThumbprintHash::SHA256));
        assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some(key.kid()));
        assert!(IdTokenKey::from_pkcs8_pem(Some("not canonical"), &pem).is_none());
        assert!(IdTokenKey::from_pkcs8_pem(None, "not a key").is_none());
    }
}
