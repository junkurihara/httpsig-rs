mod asymmetric;
mod symmetric;

use crate::error::{HttpSigError, HttpSigResult};

pub use asymmetric::{PublicKey, SecretKey};
pub use symmetric::SharedKey;

#[derive(Debug, PartialEq, Eq)]
/// Algorithm names
pub enum AlgorithmName {
  HmacSha256,
  EcdsaP256Sha256,
  EcdsaP384Sha384,
  Ed25519,
  #[cfg(feature = "rsasig")]
  RsaV1_5Sha256,
  #[cfg(feature = "rsasig")]
  RsaPssSha512,
}

impl AlgorithmName {
  pub fn as_str(&self) -> &'static str {
    match self {
      AlgorithmName::HmacSha256 => "hmac-sha256",
      AlgorithmName::EcdsaP256Sha256 => "ecdsa-p256-sha256",
      AlgorithmName::EcdsaP384Sha384 => "ecdsa-p384-sha384",
      AlgorithmName::Ed25519 => "ed25519",
      #[cfg(feature = "rsasig")]
      AlgorithmName::RsaV1_5Sha256 => "rsa-v1_5-sha256",
      #[cfg(feature = "rsasig")]
      AlgorithmName::RsaPssSha512 => "rsa-pss-sha512",
    }
  }
}

impl std::fmt::Display for AlgorithmName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
  }
}

impl core::str::FromStr for AlgorithmName {
  type Err = HttpSigError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "hmac-sha256" => Ok(Self::HmacSha256),
      "ecdsa-p256-sha256" => Ok(Self::EcdsaP256Sha256),
      "ecdsa-p384-sha384" => Ok(Self::EcdsaP384Sha384),
      "ed25519" => Ok(Self::Ed25519),
      #[cfg(feature = "rsasig")]
      "rsa-v1_5-sha256" => Ok(Self::RsaV1_5Sha256),
      #[cfg(feature = "rsasig")]
      "rsa-pss-sha512" => Ok(Self::RsaPssSha512),
      _ => Err(HttpSigError::InvalidAlgorithmName(s.to_string())),
    }
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
