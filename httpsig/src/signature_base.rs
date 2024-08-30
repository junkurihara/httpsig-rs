use crate::{
  crypto::SigningKey,
  error::{HttpSigError, HttpSigResult},
  message_component::HttpMessageComponent,
  prelude::{message_component::HttpMessageComponentId, VerifyingKey},
  signature_params::HttpSignatureParams,
};
use base64::{engine::general_purpose, Engine as _};
use fxhash::FxBuildHasher;
use indexmap::IndexMap;
use sfv::{BareItem, Item, ListEntry, Parser};

/// IndexMap of signature name and HttpSignatureHeaders
pub type HttpSignatureHeadersMap = IndexMap<String, HttpSignatureHeaders, FxBuildHasher>;

/// Default signature name used to indicate signature in http header (`signature` and `signature-input`)
const DEFAULT_SIGNATURE_NAME: &str = "sig";

#[derive(Debug, Clone)]
/// Signature Headers derived from HttpSignatureBase
pub struct HttpSignatureHeaders {
  /// signature name coupling signature with signature input
  signature_name: String,
  /// Signature value of "Signature" http header in the form of "<signature_name>=:<base64_signature>:"
  signature: HttpSignature,
  /// signature-params value of "Signature-Input" http header in the form of "<signature_name>=:<signature_params>:"
  signature_params: HttpSignatureParams,
}

impl HttpSignatureHeaders {
  /// Generates (possibly multiple) HttpSignatureHeaders from signature and signature-input header values
  pub fn try_parse(signature_header: &str, signature_input_header: &str) -> HttpSigResult<HttpSignatureHeadersMap> {
    let signature_input =
      Parser::parse_dictionary(signature_input_header.as_bytes()).map_err(|e| HttpSigError::ParseSFVError(e.to_string()))?;
    let signature =
      Parser::parse_dictionary(signature_header.as_bytes()).map_err(|e| HttpSigError::ParseSFVError(e.to_string()))?;

    if signature.len() != signature_input.len() {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The number of signature and signature-input headers are not the same".to_string(),
      ));
    }

    if !signature.keys().all(|k| signature_input.contains_key(k)) {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The signature and signature-input headers are not the same".to_string(),
      ));
    }
    if !signature.values().all(|v| {
      matches!(
        v,
        ListEntry::Item(Item {
          bare_item: BareItem::ByteSeq(_),
          ..
        })
      )
    }) {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The signature header is not a dictionary".to_string(),
      ));
    }
    if !signature_input.values().all(|v| matches!(v, ListEntry::InnerList(_))) {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The signature-input header is not a dictionary".to_string(),
      ));
    }

    let res = signature_input
      .iter()
      .map(|(k, v)| {
        let signature_name = k.to_string();
        let signature_params = HttpSignatureParams::try_from(v)?;

        let signature_bytes = match signature.get(k) {
          Some(ListEntry::Item(Item {
            bare_item: BareItem::ByteSeq(v),
            ..
          })) => v,
          _ => unreachable!(),
        };
        let signature = HttpSignature(signature_bytes.to_vec());

        Ok((
          signature_name.clone(),
          Self {
            signature_name,
            signature,
            signature_params,
          },
        )) as HttpSigResult<(String, Self)>
      })
      .collect::<Result<HttpSignatureHeadersMap, _>>()?;
    Ok(res)
  }

  /// Returns the signature name
  pub fn signature_name(&self) -> &str {
    &self.signature_name
  }

  /// Returns the signature value without name
  pub fn signature(&self) -> &HttpSignature {
    &self.signature
  }

  /// Returns the signature params value without name for signature-input header
  pub fn signature_params(&self) -> &HttpSignatureParams {
    &self.signature_params
  }

  /// Returns the signature value of "Signature" http header in the form of "<signature_name>=:<base64_signature>:"
  pub fn signature_header_value(&self) -> String {
    format!("{}=:{}:", self.signature_name, self.signature)
  }
  /// Returns the signature input value of "Signature-Input" http header in the form of "<signature_name>=<signature_params>"
  pub fn signature_input_header_value(&self) -> String {
    format!("{}={}", self.signature_name, self.signature_params)
  }
}

#[derive(Debug, Clone)]
/// Wrapper struct of raw signature bytes
pub struct HttpSignature(Vec<u8>);
impl std::fmt::Display for HttpSignature {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let signature_value = general_purpose::STANDARD.encode(&self.0);
    write!(f, "{}", signature_value)
  }
}

/// Signature Base
/// https://datatracker.ietf.org/doc/html/rfc9421#section-2.5
pub struct HttpSignatureBase {
  /// HTTP message field and derived components ordered as in the vector in signature params
  component_lines: Vec<HttpMessageComponent>,
  /// signature params
  signature_params: HttpSignatureParams,
}

impl HttpSignatureBase {
  /// Creates a new signature base from component lines and signature params
  /// This should not be exposed to user and not used directly.
  /// Use wrapper functions generating SignatureBase from base HTTP request and Signer itself instead when newly generating signature
  /// When verifying signature, use wrapper functions generating SignatureBase from HTTP request containing signature params itself instead.
  pub fn try_new(component_lines: &[HttpMessageComponent], signature_params: &HttpSignatureParams) -> HttpSigResult<Self> {
    // check if the order of component lines is the same as the order of covered message component ids
    if component_lines.len() != signature_params.covered_components.len() {
      return Err(HttpSigError::BuildSignatureBaseError(
        "The number of component lines is not the same as the number of covered message component ids".to_string(),
      ));
    }

    let assertion = component_lines
      .iter()
      .zip(signature_params.covered_components.iter())
      .all(|(component_line, covered_component_id)| component_line.id == *covered_component_id);
    if !assertion {
      return Err(HttpSigError::BuildSignatureBaseError(
        "The order of component lines is not the same as the order of covered message component ids".to_string(),
      ));
    }

    Ok(Self {
      component_lines: component_lines.to_vec(),
      signature_params: signature_params.clone(),
    })
  }

  /// Returns the signature base string as bytes to be signed
  pub fn as_bytes(&self) -> Vec<u8> {
    let string = self.to_string();
    string.as_bytes().to_vec()
  }

  /// Build signature from given signing key
  pub fn build_raw_signature(&self, signing_key: &impl SigningKey) -> HttpSigResult<Vec<u8>> {
    let bytes = self.as_bytes();
    signing_key.sign(&bytes)
  }

  /// Build the signature and signature-input headers structs
  pub fn build_signature_headers(
    &self,
    signing_key: &impl SigningKey,
    signature_name: Option<&str>,
  ) -> HttpSigResult<HttpSignatureHeaders> {
    let signature = self.build_raw_signature(signing_key)?;
    Ok(HttpSignatureHeaders {
      signature_name: signature_name.unwrap_or(DEFAULT_SIGNATURE_NAME).to_string(),
      signature: HttpSignature(signature),
      signature_params: self.signature_params.clone(),
    })
  }

  /// Verify the signature using the given verifying key
  pub fn verify_signature_headers(
    &self,
    verifying_key: &impl VerifyingKey,
    signature_headers: &HttpSignatureHeaders,
  ) -> HttpSigResult<()> {
    if signature_headers.signature_params().is_expired() {
      return Err(HttpSigError::ExpiredSignatureParams(
        "Signature params is expired".to_string(),
      ));
    }
    let signature_bytes = signature_headers.signature.0.as_slice();
    verifying_key.verify(&self.as_bytes(), signature_bytes)
  }

  /// Get key id from signature params
  pub fn keyid(&self) -> Option<&str> {
    self.signature_params.keyid.as_deref()
  }

  /// Get algorithm from signature params
  pub fn alg(&self) -> Option<&str> {
    self.signature_params.alg.as_deref()
  }

  /// Get nonce from signature params
  pub fn nonce(&self) -> Option<&str> {
    self.signature_params.nonce.as_deref()
  }

  /// Get covered components from signature params
  pub fn covered_components(&self) -> &[HttpMessageComponentId] {
    &self.signature_params.covered_components
  }
}

impl std::fmt::Display for HttpSignatureBase {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut signature_base = String::new();
    for component_line in &self.component_lines {
      signature_base.push_str(&component_line.to_string());
      signature_base.push('\n');
    }
    signature_base.push_str(&format!("\"@signature-params\": {}", self.signature_params));
    write!(f, "{}", signature_base)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::signature_params::HttpSignatureParams;

  const COMPONENT_LINES: &[&str] = &[
    r##""@method": GET"##,
    r##""@path": /"##,
    r##""date": Tue, 07 Jun 2014 20:51:35 GMT"##,
    r##""content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"##,
  ];

  /// こんな感じでSignatureBaseをParamsとかComponentLinesから直接作るのは避ける。
  #[test]
  fn test_signature_base_directly_instantiated() {
    const SIGPARA: &str = r##";created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=""##;
    let values = (r##""@method" "@path" "date" "content-digest""##, SIGPARA);
    let signature_params = HttpSignatureParams::try_from(format!("({}){}", values.0, values.1).as_str()).unwrap();

    let component_lines = COMPONENT_LINES
      .iter()
      .map(|&s| HttpMessageComponent::try_from(s))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let signature_base = HttpSignatureBase::try_new(&component_lines, &signature_params).unwrap();
    let test_string = r##""@method": GET
"@path": /
"date": Tue, 07 Jun 2014 20:51:35 GMT
"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
"@signature-params": "##;
    assert_eq!(
      signature_base.to_string(),
      format!("{}({}){}", test_string, values.0, values.1)
    );
  }

  #[test]
  fn test_signature_values() {
    const SIGNATURE_INPUT: &str = r##"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519", sig-b27=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519-alt""##;
    const SIGNATURE: &str = r##"sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:, sig-b27=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"##;

    let header_map = HttpSignatureHeaders::try_parse(SIGNATURE, SIGNATURE_INPUT).unwrap();
    assert!(header_map.len() == 2);
    let http_signature_headers = header_map.get("sig-b26").unwrap();
    assert_eq!(
      http_signature_headers.signature_header_value(),
      SIGNATURE.split(',').next().unwrap()
    );
    assert_eq!(
      http_signature_headers.signature_input_header_value(),
      SIGNATURE_INPUT.split(',').next().unwrap()
    );
  }
}
