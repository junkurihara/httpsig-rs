use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/* -------------------------------- */
/// Shared key for http signature
/// Name conventions follow [the IETF draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-6.2.2)
pub enum SharedKey {
  /// hmac-sha256
  HmacSha256(Vec<u8>),
}

impl super::Signer for SharedKey {
  /// Sign the data
  fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
    match self {
      SharedKey::HmacSha256(key) => {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
      }
    }
  }
  /// Get the key id
  fn key_id(&self) -> String {
    use super::Verifier;
    <Self as Verifier>::key_id(self)
  }
}
impl super::Verifier for SharedKey {
  /// Verify the mac
  fn verify(&self, data: &[u8], expected_mac: &[u8]) -> Result<()> {
    use super::Signer;
    let calcurated_mac = self.sign(data)?;
    if calcurated_mac == expected_mac {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Invalid mac"))
    }
  }

  /// Get the key id
  fn key_id(&self) -> String {
    use base64::{engine::general_purpose, Engine as _};
    match self {
      SharedKey::HmacSha256(key) => {
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(&key);
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
    use super::super::{Signer, Verifier};
    let inner = b"01234567890123456789012345678901";
    let key = SharedKey::HmacSha256(inner.to_vec());
    let data = b"hello";
    let signature = key.sign(data).unwrap();
    key.verify(data, &signature).unwrap();
  }
}
