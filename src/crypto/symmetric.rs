use super::MINIMUM_SYMMETRIC_KEY_LENGTH;
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
  pub inner: Vec<u8>,
}

impl From<&[u8]> for SymmetricKey {
  fn from(value: &[u8]) -> Self {
    if value.len() < MINIMUM_SYMMETRIC_KEY_LENGTH {
      panic!("Key length is too short (minimum: {})", MINIMUM_SYMMETRIC_KEY_LENGTH);
    }
    SymmetricKey { inner: value.to_vec() }
  }
}

impl SecretKey {
  /// Sign the data
  pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
    match self {
      SecretKey::HmacSha256(key) => {
        let mut mac = HmacSha256::new_from_slice(&key.inner).unwrap();
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
      }
    }
  }
  /// Verify the mac
  pub fn verify(&self, data: &[u8], expected_mac: &[u8]) -> Result<()> {
    let calcurated_mac = self.sign(data)?;
    if calcurated_mac == expected_mac {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Invalid mac"))
    }
  }

  /// Get the key id
  pub fn key_id(&self) -> String {
    use base64::{engine::general_purpose, Engine as _};
    match self {
      SecretKey::HmacSha256(key) => {
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(&key.inner);
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
    let inner = b"01234567890123456789012345678901";
    let key = SymmetricKey::from(inner.as_slice());
    let sk = SecretKey::HmacSha256(key);
    let data = b"hello";
    let signature = sk.sign(data).unwrap();
    sk.verify(data, &signature).unwrap();
  }
}
