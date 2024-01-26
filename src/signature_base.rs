use crate::{message_component::HttpMessageComponent, signature_params::HttpSignatureParams};

/// Signature Base
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.5
pub(crate) struct SignatureBase {
  /// HTTP message field and derived components ordered as in the vector in signature params
  component_lines: Vec<HttpMessageComponent>,
  /// signature params
  signature_params: HttpSignatureParams,
}

impl SignatureBase {
  /// Creates a new signature base from component lines and signature params
  /// This should not be exposed to user and not used directly.
  /// TODO: Use wrapper functions generating SignatureBase from base HTTP request and SignatureParamsBuilder itself instead when newly generating signature
  /// TODO: When verifying signature, use wrapper functions generating SignatureBase from HTTP request containing signature params itself instead.
  pub(crate) fn try_new(
    component_lines: &Vec<HttpMessageComponent>,
    signature_params: &HttpSignatureParams,
  ) -> anyhow::Result<Self> {
    // check if the order of component lines is the same as the order of covered message component ids
    if component_lines.len() != signature_params.covered_components.len() {
      anyhow::bail!("The number of component lines is not the same as the number of covered message component ids");
    }

    let assertion = component_lines
      .iter()
      .zip(signature_params.covered_components.iter())
      .all(|(component_line, covered_component_id)| {
        let component_line_id_string = &component_line.id.to_string();
        component_line_id_string == covered_component_id
      });
    if !assertion {
      anyhow::bail!("The order of component lines is not the same as the order of covered message component ids");
    }

    Ok(Self {
      component_lines: component_lines.clone(),
      signature_params: signature_params.clone(),
    })
  }

  /// Returns the signature base string as bytes to be signed
  pub(crate) fn as_bytes(&self) -> Vec<u8> {
    let string = self.to_string();
    string.as_bytes().to_vec()
  }
}

impl std::fmt::Display for SignatureBase {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut signature_base = String::new();
    for component_line in &self.component_lines {
      signature_base.push_str(&component_line.to_string());
      signature_base.push('\n');
    }
    signature_base.push_str(&format!("\"@signature-params\": {}", self.signature_params.to_string()));
    write!(f, "{}", signature_base)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::signature_params::HttpSignatureParamsBuilder;

  #[test]
  fn test_signature_base() {
    let mut signature_params = HttpSignatureParamsBuilder::default();
    signature_params.created(1706091731);
    signature_params.key_id("key_id");
    signature_params.algorithm("rsa-sha256");
    signature_params.covered_message_component_ids(&["\"@method\";req", "\"date\"", "\"content-digest\""]);
    let signature_params = signature_params.build();

    let component_lines = vec![
      HttpMessageComponent::try_from(("\"@method\";req", "GET")).unwrap(),
      HttpMessageComponent::try_from(("\"date\"", "Tue, 07 Jun 2014 20:51:35 GMT")).unwrap(),
      HttpMessageComponent::try_from((
        "\"content-digest\"",
        "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
      ))
      .unwrap(),
    ];
    let signature_base = SignatureBase::try_new(&component_lines, &signature_params).unwrap();
    let test_string = r##""@method";req: GET
"date": Tue, 07 Jun 2014 20:51:35 GMT
"content-digest": SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
"@signature-params": ("@method";req "date" "content-digest");created=1706091731;alg="rsa-sha256";keyid="key_id""##;
    assert_eq!(signature_base.to_string(), test_string);
  }
}
