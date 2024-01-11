use crate::{message_component::HttpMessageComponent, signature_params::HttpSignatureParams};

/// Signature Base
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.5
struct SignatureBase {
  /// HTTP message field and derived components ordered as in the vector in signature params
  component_lines: Vec<HttpMessageComponent>,
  /// signature params
  signature_params: HttpSignatureParams,
}

// creating signature base from http header lines and signature params builder config

// creating signature base from http header lines including signature params
