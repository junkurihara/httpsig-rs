mod asymmetric;
mod symmetric;

pub use asymmetric::{PublicKey, SecretKey};
pub use symmetric::SharedKey;

/// Signer trait
pub trait Signer {
  fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
  fn key_id(&self) -> String;
}

/// Verifier trait
pub trait Verifier {
  fn verify(&self, data: &[u8], signature: &[u8]) -> anyhow::Result<()>;
  fn key_id(&self) -> String;
}
