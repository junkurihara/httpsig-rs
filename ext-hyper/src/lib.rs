mod hyper_content_digest;
mod hyper_http;

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

// TODO: creating signature base from http header lines and signature params builder config

// TODO: creating signature base from http header lines including signature params

// TODO: These should be given as a trait

// /// A trait to generate the http message signature
// /// TODO: signature params should be given as a trait
// pub trait HttpMessageSignature {
//   fn message_signature(&self) -> String;
// }
