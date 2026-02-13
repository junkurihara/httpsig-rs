use super::AlgorithmName;
use crate::{
  error::{HttpSigError, HttpSigResult},
  trace::*,
};
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<sha2::Sha256>;

/* -------------------------------- */
#[derive(Debug, Clone)]
/// Shared key for http signature
/// Name conventions follow [Section 6.2.2, RFC9421](https://datatracker.ietf.org/doc/html/rfc9421#section-6.2.2)
pub enum SharedKey {
  /// hmac-sha256
  HmacSha256(Vec<u8>),
}

impl SharedKey {
  /// Create a new shared key from base64 encoded string
  pub fn from_base64(alg: &AlgorithmName, key: &str) -> HttpSigResult<Self> {
    debug!("Create SharedKey from base64 string");
    let key = general_purpose::STANDARD.decode(key)?;
    match alg {
      AlgorithmName::HmacSha256 => Ok(SharedKey::HmacSha256(key)),
      _ => Err(HttpSigError::InvalidAlgorithmName(format!(
        "Unsupported algorithm for SharedKey: {}",
        alg
      ))),
    }
  }
}

impl super::SigningKey for SharedKey {
  /// Sign the data
  fn sign(&self, data: &[u8]) -> HttpSigResult<Vec<u8>> {
    match self {
      SharedKey::HmacSha256(key) => {
        debug!("Sign HmacSha256");
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
  fn verify(&self, data: &[u8], expected_mac: &[u8]) -> HttpSigResult<()> {
    match self {
      SharedKey::HmacSha256(key) => {
        debug!("Verify HmacSha256");
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        mac
          .verify_slice(expected_mac)
          .map_err(|_| HttpSigError::InvalidSignature("Invalid MAC".to_string()))
      }
    }
  }

  /// Get the key id
  fn key_id(&self) -> String {
    match self {
      SharedKey::HmacSha256(key) => {
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(key);
        let hash = hasher.finalize();
        general_purpose::STANDARD.encode(hash)
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
    let res = key.verify(data, &signature);
    assert!(res.is_ok());
  }
}
