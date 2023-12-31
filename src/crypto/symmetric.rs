use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/* -------------------------------- */
/// Secret key for http signature
/// Name conventions follow [the IETF draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-6.2.2)
pub enum SecretKey {
  /// hmac-sha256
  HmacSha256(SymmetricKey),
}

/// Symmetric key
pub struct SymmetricKey {
  /// Key value
  pub key: Vec<u8>,
}

impl From<&[u8]> for SecretKey {
  fn from(value: &[u8]) -> Self {
    match value.len() {
      32 => SecretKey::HmacSha256(SymmetricKey { key: value.to_vec() }),
      _ => panic!("Unsupported key length"),
    }
  }
}

impl SecretKey {
  /// Sign the data
  pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
    match self {
      SecretKey::HmacSha256(key) => {
        let mut mac = HmacSha256::new_from_slice(&key.key).unwrap();
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
      }
    }
  }
  /// Verify the signature
  pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
    match self {
      SecretKey::HmacSha256(key) => {
        let mut mac = HmacSha256::new_from_slice(&key.key).unwrap();
        mac.update(data);
        mac.verify(signature.into()).map_err(|e| anyhow::anyhow!(e))?;
        Ok(())
      }
    }
  }

  /// Get the key id
  pub fn key_id(&self) -> String {
    use base64::{engine::general_purpose, Engine as _};
    match self {
      SecretKey::HmacSha256(key) => {
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(&key.key);
        let hash = hasher.finalize();
        general_purpose::URL_SAFE_NO_PAD.encode(hash)
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn symmetric_key_works() {
    let key = SymmetricKey { key: vec![1, 2, 3] };
    let sk = SecretKey::HmacSha256(key);
    let data = b"hello";
    let signature = sk.sign(data).unwrap();
    sk.verify(data, &signature).unwrap();
  }
}
