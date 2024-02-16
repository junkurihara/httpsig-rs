use super::AlgorithmName;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<sha2::Sha256>;

/* -------------------------------- */
/// Shared key for http signature
/// Name conventions follow [the IETF draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-6.2.2)
pub enum SharedKey {
  /// hmac-sha256
  HmacSha256(Vec<u8>),
}

impl SharedKey {
  /// Create a new shared key from base64 encoded string
  pub fn from_base64(key: &str) -> Result<Self> {
    let key = general_purpose::STANDARD.decode(key)?;
    Ok(SharedKey::HmacSha256(key))
  }
}

impl super::SigningKey for SharedKey {
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
    use super::VerifyingKey;
    <Self as VerifyingKey>::key_id(self)
  }
  /// Get the algorithm name
  fn alg(&self) -> AlgorithmName {
    use super::VerifyingKey;
    <Self as VerifyingKey>::alg(self)
  }
}
impl super::VerifyingKey for SharedKey {
  /// Verify the mac
  fn verify(&self, data: &[u8], expected_mac: &[u8]) -> Result<()> {
    use super::SigningKey;
    let calcurated_mac = self.sign(data)?;
    if calcurated_mac == expected_mac {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Invalid mac"))
    }
  }

  /// Get the key id
  fn key_id(&self) -> String {
    match self {
      SharedKey::HmacSha256(key) => {
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(key);
        let hash = hasher.finalize();
        general_purpose::URL_SAFE_NO_PAD.encode(hash)
      }
    }
  }
  /// Get the algorithm name
  fn alg(&self) -> AlgorithmName {
    match self {
      SharedKey::HmacSha256(_) => AlgorithmName::HmacSha256,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn symmetric_key_works() {
    use super::super::{SigningKey, VerifyingKey};
    let inner = b"01234567890123456789012345678901";
    let key = SharedKey::HmacSha256(inner.to_vec());
    let data = b"hello";
    let signature = key.sign(data).unwrap();
    key.verify(data, &signature).unwrap();
  }
}
