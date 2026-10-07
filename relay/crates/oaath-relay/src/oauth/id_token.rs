//! The relay's ES256 id_token key and its public JWKS.
//!
//! One P-256 key from a PKCS#8 PEM file, identified by a configured `kid`.
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

use crate::error::{RelayErrorCode, RelayResult};
use crate::records::canonical_str;

pub struct IdTokenKey {
    kid: String,
    encoding: EncodingKey,
    jwks: Value,
}

impl IdTokenKey {
    /// Parses a PKCS#8 PEM P-256 private key. Failures never echo the key.
    pub fn from_pkcs8_pem(kid: &str, pem: &str) -> Option<Self> {
        canonical_str(kid, RelayErrorCode::Internal).ok()?;
        let secret = SecretKey::from_pkcs8_pem(pem).ok()?;
        let point = secret.public_key().to_encoded_point(false);
        let encoding = EncodingKey::from_ec_pem(pem.as_bytes()).ok()?;
        let jwks = json!({ "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x()?),
            "y": URL_SAFE_NO_PAD.encode(point.y()?),
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
        }] });
        Some(Self {
            kid: kid.to_owned(),
            encoding,
            jwks,
        })
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
