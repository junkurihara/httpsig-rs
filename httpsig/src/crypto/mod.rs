#[cfg(any(
  feature = "ed25519-signature",
  feature = "ecdsa-p256-sha256-signature",
  feature = "ecdsa-p384-sha384-signature",
  feature = "rsa-signature"
))]
mod asymmetric;
#[cfg(feature = "hmac-sha256-signature")]
mod symmetric;

use crate::error::{HttpSigError, HttpSigResult};

#[cfg(any(
  feature = "ed25519-signature",
  feature = "ecdsa-p256-sha256-signature",
  feature = "ecdsa-p384-sha384-signature",
  feature = "rsa-signature"
))]
pub use asymmetric::{PublicKey, SecretKey};
#[cfg(feature = "hmac-sha256-signature")]
pub use symmetric::SharedKey;

#[derive(Debug, PartialEq, Eq)]
/// Algorithm names
pub enum AlgorithmName {
  #[cfg(feature = "hmac-sha256-signature")]
  HmacSha256,
  #[cfg(feature = "ecdsa-p256-sha256-signature")]
  /// ecdsa-p256-sha256
  EcdsaP256Sha256,
  #[cfg(feature = "ecdsa-p384-sha384-signature")]
  EcdsaP384Sha384,
  #[cfg(feature = "ed25519-signature")]
  Ed25519,
  #[cfg(feature = "rsa-signature")]
  RsaV1_5Sha256,
  #[cfg(feature = "rsa-signature")]
  RsaPssSha512,
}

impl AlgorithmName {
  pub fn as_str(&self) -> &'static str {
    match self {
      #[cfg(feature = "hmac-sha256-signature")]
      AlgorithmName::HmacSha256 => "hmac-sha256",
      #[cfg(feature = "ecdsa-p256-sha256-signature")]
      AlgorithmName::EcdsaP256Sha256 => "ecdsa-p256-sha256",
      #[cfg(feature = "ecdsa-p384-sha384-signature")]
      AlgorithmName::EcdsaP384Sha384 => "ecdsa-p384-sha384",
      #[cfg(feature = "ed25519-signature")]
      AlgorithmName::Ed25519 => "ed25519",
      #[cfg(feature = "rsa-signature")]
      AlgorithmName::RsaV1_5Sha256 => "rsa-v1_5-sha256",
      #[cfg(feature = "rsa-signature")]
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
      #[cfg(feature = "hmac-sha256-signature")]
      "hmac-sha256" => Ok(Self::HmacSha256),
      #[cfg(feature = "ecdsa-p256-sha256-signature")]
      "ecdsa-p256-sha256" => Ok(Self::EcdsaP256Sha256),
      #[cfg(feature = "ecdsa-p384-sha384-signature")]
      "ecdsa-p384-sha384" => Ok(Self::EcdsaP384Sha384),
      #[cfg(feature = "ed25519-signature")]
      "ed25519" => Ok(Self::Ed25519),
      #[cfg(feature = "rsa-signature")]
      "rsa-v1_5-sha256" => Ok(Self::RsaV1_5Sha256),
      #[cfg(feature = "rsa-signature")]
      "rsa-pss-sha512" => Ok(Self::RsaPssSha512),
      _ => Err(HttpSigError::InvalidAlgorithmName(s.to_string())),
    }
  }
}

/// SigningKey trait
pub trait SigningKey {
  fn sign(&self, data: &[u8]) -> HttpSigResult<Vec<u8>>;
  #[cfg(feature = "key-id")]
  fn key_id(&self) -> String;
  fn alg(&self) -> AlgorithmName;
}

/// VerifyingKey trait
pub trait VerifyingKey {
  fn verify(&self, data: &[u8], signature: &[u8]) -> HttpSigResult<()>;
  #[cfg(feature = "key-id")]
  fn key_id(&self) -> String;
  fn alg(&self) -> AlgorithmName;
}
