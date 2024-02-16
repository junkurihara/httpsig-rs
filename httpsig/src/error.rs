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
  /// Invalid Signature
  #[error("Invalid Signature: {0}")]
  InvalidSignature(String),

  /* ----- Component errors ----- */
  /// Failed to parse structured field value
  #[error("Failed to parse structured field value: {0}")]
  ParseSFVError(String),
  /// Invalid http message component name
  #[error("Invalid http message component name: {0}")]
  InvalidComponentName(String),
  /// Invalid http message component param
  #[error("Invalid http message component param: {0}")]
  InvalidComponentParam(String),
  /// Invalid http message component id
  #[error("Invalid http message component id: {0}")]
  InvalidComponentId(String),
  /// Invalid http message component
  #[error("Invalid http message component: {0}")]
  InvalidComponent(String),

  /* ----- Other errors ----- */
  /// Others
  #[error("Others: {0}")]
  Others(#[from] anyhow::Error),
}
