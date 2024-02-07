mod hyper_content_digest;
mod hyper_http;

// hyper's http specific extension to generate and verify http signature

/// content-digest header name
const CONTENT_DIGEST_HEADER: &str = "content-digest";

/// content-digest header type
pub enum ContentDigestType {
  Sha256,
  Sha512,
}

impl std::fmt::Display for ContentDigestType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ContentDigestType::Sha256 => write!(f, "sha-256"),
      ContentDigestType::Sha512 => write!(f, "sha-512"),
    }
  }
}

pub use hyper_content_digest::{ContentDigest, RequestContentDigest};
pub use hyper_http::RequestMessageSignature;
