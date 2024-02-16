use thiserror::Error;

/// Result type for http signature
pub type HttpSigResult<T> = std::result::Result<T, HttpSigError>;

/// Error type for http signature
#[derive(Error, Debug)]
pub enum HttpSigError {
  #[error("Base64 decode error: {0}")]
  Base64DecodeError(#[from] base64::DecodeError),

  /* ----- Crypto errors ----- */
  /// Invalid private key for asymmetric algorithm
  #[error("Failed to parse private key: {0}")]
  ParsePrivateKeyError(String),
  /// Invalid public key for asymmetric algorithm
  #[error("Failed to parse public key: {0}")]
  ParsePublicKeyError(String),

  /// Signature parse error
  #[error("Failed to parse signature: {0}")]
  ParseSignatureError(String),

  // #[error("Failed to verify digest: {0}")]
  // VerifyDigestError(#[from] ),
  /// Invalid Signature
  #[error("Invalid Signature: {0}")]
  InvalidSignature(String),
}
