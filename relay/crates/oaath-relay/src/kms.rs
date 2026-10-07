//! Deployment-owned encryption port and the relay's sealing boundary.
//!
//! The relay stores only the opaque reference the port returns. Plaintext never
//! reaches the store.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{bounded_str, limits};

/// The port could not answer. The relay projects it to `relay_kms_unavailable`.
#[derive(Debug)]
pub struct KmsUnavailable;

#[async_trait]
pub trait RelayKms: Send + Sync {
    /// Returns an opaque bounded string reference for the ciphertext.
    async fn encrypt(&self, plaintext: &str) -> Result<String, KmsUnavailable>;
    /// Returns the plaintext for a reference this port previously returned.
    async fn decrypt(&self, ciphertext_ref: &str) -> Result<String, KmsUnavailable>;
}

const KMS_UNAVAILABLE: RelayErrorCode = RelayErrorCode::KmsUnavailable;

/// Encrypts a plaintext and returns the opaque reference to store. A port that
/// echoes plaintext is rejected: the store must never hold it.
pub async fn seal_artifact(kms: &dyn RelayKms, plaintext: &str) -> RelayResult<String> {
    let sealed = kms.encrypt(plaintext).await.map_err(|_| KMS_UNAVAILABLE)?;
    bounded_str(&sealed, limits::CIPHERTEXT_REF, KMS_UNAVAILABLE)?;
    if sealed.contains(plaintext) {
        return Err(KMS_UNAVAILABLE);
    }
    Ok(sealed)
}

/// Opens retained ciphertext for an authorized reader.
pub async fn open_artifact(kms: &dyn RelayKms, ciphertext_ref: &str) -> RelayResult<String> {
    let opened = kms
        .decrypt(ciphertext_ref)
        .await
        .map_err(|_| KMS_UNAVAILABLE)?;
    bounded_str(&opened, limits::ARTIFACT_PLAINTEXT, KMS_UNAVAILABLE)?;
    Ok(opened)
}

const AES_GCM_PREFIX: &str = "oaath-kms-aes256gcm:v1:";
const NONCE_BYTES: usize = 12;

/// AES-256-GCM envelope encryption under one deployment-held 32-byte key.
///
/// The reference is `oaath-kms-aes256gcm:v1:` followed by base64url of
/// `nonce (12 bytes) || ciphertext || tag`. Each seal uses a fresh random nonce.
pub struct AesGcmKms {
    cipher: Aes256Gcm,
}

impl AesGcmKms {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key)),
        }
    }

    /// Parses a 64-character hex key. The key itself never appears in errors.
    pub fn from_hex(hex_key: &str) -> Option<Self> {
        let bytes: [u8; 32] = hex::decode(hex_key.trim()).ok()?.try_into().ok()?;
        Some(Self::new(&bytes))
    }
}

#[async_trait]
impl RelayKms for AesGcmKms {
    async fn encrypt(&self, plaintext: &str) -> Result<String, KmsUnavailable> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| KmsUnavailable)?;
        let mut envelope = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(format!(
            "{AES_GCM_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(envelope)
        ))
    }

    async fn decrypt(&self, ciphertext_ref: &str) -> Result<String, KmsUnavailable> {
        let encoded = ciphertext_ref
            .strip_prefix(AES_GCM_PREFIX)
            .ok_or(KmsUnavailable)?;
        let envelope = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| KmsUnavailable)?;
        if envelope.len() < NONCE_BYTES {
            return Err(KmsUnavailable);
        }
        let (nonce, ciphertext) = envelope.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| KmsUnavailable)?;
        let plaintext = self
            .cipher
            .decrypt(&Nonce::from(nonce), ciphertext)
            .map_err(|_| KmsUnavailable)?;
        String::from_utf8(plaintext).map_err(|_| KmsUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_and_refuses_foreign_or_tampered_references() {
        let kms = AesGcmKms::new(&[7u8; 32]);
        let sealed = seal_artifact(&kms, "artifact plaintext").await.unwrap();
        assert!(sealed.starts_with(AES_GCM_PREFIX));
        assert!(!sealed.contains("artifact plaintext"));
        assert_ne!(
            sealed,
            seal_artifact(&kms, "artifact plaintext").await.unwrap()
        );
        assert_eq!(
            open_artifact(&kms, &sealed).await.unwrap(),
            "artifact plaintext"
        );

        let other = AesGcmKms::new(&[8u8; 32]);
        assert_eq!(
            open_artifact(&other, &sealed).await,
            Err(RelayErrorCode::KmsUnavailable)
        );
        let mut tampered = sealed.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            open_artifact(&kms, &tampered).await,
            Err(RelayErrorCode::KmsUnavailable)
        );
        assert!(AesGcmKms::from_hex("00").is_none());
        assert!(AesGcmKms::from_hex(&"ab".repeat(32)).is_some());
    }
}
