mod asymmetric;
mod symmetric;

pub use asymmetric::{PublicKey, SecretKey};
pub use symmetric::SharedKey;

/// SigningKey trait
pub trait SigningKey {
  fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
  fn key_id(&self) -> String;
  fn alg(&self) -> String;
}

/// VerifyingKey trait
pub trait VerifyingKey {
  fn verify(&self, data: &[u8], signature: &[u8]) -> anyhow::Result<()>;
  fn key_id(&self) -> String;
  fn alg(&self) -> String;
}
