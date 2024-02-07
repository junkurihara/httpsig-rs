use crate::{message_component::HttpMessageComponent, signature_params::HttpSignatureParams};

/// Signature Base
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.5
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
  pub fn try_new(component_lines: &Vec<HttpMessageComponent>, signature_params: &HttpSignatureParams) -> anyhow::Result<Self> {
    // check if the order of component lines is the same as the order of covered message component ids
    if component_lines.len() != signature_params.covered_components.len() {
      anyhow::bail!("The number of component lines is not the same as the number of covered message component ids");
    }

    let assertion = component_lines
      .iter()
      .zip(signature_params.covered_components.iter())
      .all(|(component_line, covered_component_id)| component_line.id == *covered_component_id);
    if !assertion {
      anyhow::bail!("The order of component lines is not the same as the order of covered message component ids");
    }

    Ok(Self {
      component_lines: component_lines.clone(),
      signature_params: signature_params.clone(),
    })
  }

  /// Returns the signature base string as bytes to be signed
  pub fn as_bytes(&self) -> Vec<u8> {
    let string = self.to_string();
    string.as_bytes().to_vec()
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

  /// BuilderかSignerか何かでSignatureParamsを、verify時はreqか、sign時は内部に持つ生成フラグから内部的に生成できるようにする。
  /// こんな感じでSignatureBaseをParamsとかComponentLinesから直接作るのは避ける。
  #[test]
  fn test_signature_base_directly_instantiated() {
    const SIGPARA: &str = r##";created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is""##;
    let values = (r##""@method" "@path" "date" "content-digest""##, SIGPARA);
    let signature_params = HttpSignatureParams::try_from(format!("({}){}", values.0, values.1).as_str()).unwrap();

    let component_lines = vec![
      HttpMessageComponent::try_from("\"@method\": GET").unwrap(),
      HttpMessageComponent::try_from("\"@path\": /").unwrap(),
      HttpMessageComponent::try_from("\"date\": Tue, 07 Jun 2014 20:51:35 GMT").unwrap(),
      HttpMessageComponent::try_from("\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
        .unwrap(),
    ];
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
}
