mod asymmetric;
mod symmetric;

use crate::error::HttpSigResult;

pub use asymmetric::{PublicKey, SecretKey};
pub use symmetric::SharedKey;

/// Algorithm names
pub enum AlgorithmName {
  HmacSha256,
  EcdsaP256Sha256,
  EcdsaP384Sha384,
  Ed25519,
}

impl AlgorithmName {
  pub fn as_str(&self) -> &str {
    match self {
      AlgorithmName::HmacSha256 => "hmac-sha256",
      AlgorithmName::EcdsaP256Sha256 => "ecdsa-p256-sha256",
      AlgorithmName::EcdsaP384Sha384 => "ecdsa-p384-sha384",
      AlgorithmName::Ed25519 => "ed25519",
    }
  }
}

impl std::fmt::Display for AlgorithmName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
  }
}

/// SigningKey trait
pub trait SigningKey {
  fn sign(&self, data: &[u8]) -> HttpSigResult<Vec<u8>>;
  fn key_id(&self) -> String;
  fn alg(&self) -> AlgorithmName;
}

/// VerifyingKey trait
pub trait VerifyingKey {
  fn verify(&self, data: &[u8], signature: &[u8]) -> HttpSigResult<()>;
  fn key_id(&self) -> String;
  fn alg(&self) -> AlgorithmName;
}
