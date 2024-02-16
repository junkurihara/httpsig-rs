use httpsig::prelude::HttpSigError;
use thiserror::Error;

/// Result type for http signature
pub type HyperSigResult<T> = std::result::Result<T, HyperSigError>;

/// Error type for http signature for hyper
#[derive(Error, Debug)]
pub enum HyperSigError {
  /// No signature headers found
  #[error("No signature headers found: {0}")]
  NoSignatureHeaders(String),

  /// Failed to parse signature headers
  #[error("Failed to stringify signature headers: {0}")]
  FailedToStrSignatureHeaders(#[from] http::header::ToStrError),

  /// Failed to parse header value
  #[error("Failed to parse header value: {0}")]
  InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),

  /// Invalid component name
  #[error("Invalid component name: {0}")]
  InvalidComponentName(String),

  /// Invalid component param
  #[error("Invalid component param: {0}")]
  InvalidComponentParam(String),

  /// Invalid signature
  #[error("Invalid signature: {0}")]
  InvalidSignature(String),

  /// Inherited from HttpSigError
  #[error("HttpSigError: {0}")]
  HttpSigError(#[from] HttpSigError),
}

/// Result type for http signature
pub type HyperDigestResult<T> = std::result::Result<T, HyperDigestError>;

/// Error type for http signature for hyper
#[derive(Error, Debug)]
pub enum HyperDigestError {
  /// Http body error
  #[error("Http body error: {0}")]
  HttpBodyError(String),

  /// No content-digest header found
  #[error("No content-digest header found: {0}")]
  NoDigestHeader(String),

  /// Failed to parse header value
  #[error("Failed to parse header value: {0}")]
  InvalidHeaderValue(String),

  /// Failed to parse content digest headers
  #[error("Failed to stringify content-digest header: {0}")]
  FailedToStrDigestHeader(#[from] http::header::ToStrError),

  /// Invalid content-digest
  #[error("Invalid content-digest: {0}")]
  InvalidContentDigest(String),

  /// Invalid content-digest type
  #[error("Invalid content-digest type: {0}")]
  InvalidContentDigestType(String),
}
