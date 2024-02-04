use anyhow::{bail, ensure};
use async_trait::async_trait;
use http::Request;
use http_body::Body;
use httpsig::prelude::{
  message_component::{
    build_http_message_component, DerivedComponentName, HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
    HttpMessageComponentParam,
  },
  HttpSignatureBase, HttpSignatureParams,
};
//

// hyper's http specific extension to generate and verify http signature

/* --------------------------------------- */
#[async_trait]
/// A trait to set the http message signature from given http signature params
pub trait HyperRequestMessageSignature {
  type Error;
  async fn set_message_signature(&mut self, signature_params: &HttpSignatureParams) -> std::result::Result<(), Self::Error>
  where
    Self: Sized;
}

#[async_trait]
impl<D> HyperRequestMessageSignature for Request<D>
where
  D: Send + Body,
{
  type Error = anyhow::Error;

  async fn set_message_signature(&mut self, signature_params: &HttpSignatureParams) -> std::result::Result<(), Self::Error>
  where
    Self: Sized,
  {
    // let component_lines = signature_params
    //   .covered_components
    //   .iter()
    //   .map(|component_id_str| {
    //     let component_id = HttpMessageComponentName::from(component_id_str.as_str());

    //     extract_component_from_request(self, &component_id)
    //   })
    //   .collect::<Vec<_>>();

    // anyhow::ensure!(component_lines.iter().all(|c| c.is_ok()), "Failed to extract component lines");
    // let component_lines = component_lines.into_iter().map(|c| c.unwrap()).collect::<Vec<_>>();

    // let signature_base = SignatureBase::try_new(&component_lines, signature_params);

    Ok(())
  }
}
/* --------------------------------------- */
/// Build signature base from hyper http request and signature params
fn build_signature_base_from_request<B>(
  req: &Request<B>,
  signature_params: &HttpSignatureParams,
) -> anyhow::Result<HttpSignatureBase> {
  let component_lines = signature_params
    .covered_components
    .iter()
    .map(|component_id| extract_http_message_component_from_request(req, component_id))
    .collect::<Vec<_>>();
  ensure!(component_lines.iter().all(|c| c.is_ok()), "Failed to extract component lines");
  let component_lines = component_lines.into_iter().map(|c| c.unwrap()).collect::<Vec<_>>();

  HttpSignatureBase::try_new(&component_lines, signature_params)
}

/// Extract http field from hyper http request
fn extract_http_field_from_request<B>(
  req: &Request<B>,
  id: &HttpMessageComponentId,
) -> Result<HttpMessageComponent, anyhow::Error> {
  let HttpMessageComponentName::HttpField(header_name) = &id.name else {
    bail!("invalid http message component name as http field");
  };
  anyhow::ensure!(
    !id.params.0.contains(&HttpMessageComponentParam::Req),
    "`req` is not allowed in request"
  );

  let field_values = req
    .headers()
    .get_all(header_name)
    .iter()
    .map(|v| v.to_str().map_err(|e| anyhow::anyhow!("{e}")))
    .collect::<Vec<_>>();
  ensure!(field_values.iter().all(|v| v.is_ok()), "Failed to extract field values");
  let field_values = field_values.into_iter().map(|v| v.unwrap().to_owned()).collect::<Vec<_>>();

  build_http_message_component(id, &field_values)
}

/// Extract derived component from hyper http request
fn extract_derived_component_from_request<B>(
  req: &Request<B>,
  id: &HttpMessageComponentId,
) -> Result<HttpMessageComponent, anyhow::Error> {
  let HttpMessageComponentName::Derived(derived_id) = &id.name else {
    bail!("invalid http message component name as derived component");
  };
  if !id.params.0.is_empty() {
    bail!("derived component does not allow parameters for request");
  }

  let field_values: Vec<String> = match derived_id {
    DerivedComponentName::Method => vec![req.method().as_str().to_string()],
    DerivedComponentName::TargetUri => vec![req.uri().to_string()],
    DerivedComponentName::Authority => vec![req.uri().authority().map(|s| s.to_string()).unwrap_or("".to_string())],
    DerivedComponentName::Scheme => vec![req.uri().scheme_str().unwrap_or("").to_string()],
    DerivedComponentName::RequestTarget => match *req.method() {
      http::Method::CONNECT => vec![req.uri().authority().map(|s| s.to_string()).unwrap_or("".to_string())],
      http::Method::OPTIONS => vec!["*".to_string()],
      _ => vec![req.uri().path_and_query().map(|s| s.to_string()).unwrap_or("".to_string())],
    },
    DerivedComponentName::Path => vec![{
      let p = req.uri().path();
      if p.is_empty() {
        "/".to_string()
      } else {
        p.to_string()
      }
    }],
    DerivedComponentName::Query => vec![req.uri().query().map(|v| format!("?{v}")).unwrap_or("?".to_string())],
    DerivedComponentName::QueryParam => {
      let query = req.uri().query().unwrap_or("");
      query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    }
    DerivedComponentName::Status => bail!("`status` is only for response"),
    DerivedComponentName::SignatureParams => req
      .headers()
      .get_all("signature-input")
      .iter()
      .map(|v| v.to_str().unwrap_or("").to_string())
      .collect::<Vec<_>>(),
  };

  build_http_message_component(id, &field_values)
}

/* --------------------------------------- */
/// Extract http message component from hyper http request
fn extract_http_message_component_from_request<B>(
  req: &Request<B>,
  target_component_id: &HttpMessageComponentId,
) -> Result<HttpMessageComponent, anyhow::Error> {
  match &target_component_id.name {
    HttpMessageComponentName::HttpField(_) => extract_http_field_from_request(req, target_component_id),
    HttpMessageComponentName::Derived(_) => extract_derived_component_from_request(req, target_component_id),
  }
}

/* --------------------------------------- */
#[cfg(test)]
mod tests {
  use super::super::{hyper_content_digest::HyperRequestContentDigest, ContentDigestType};
  use super::*;
  use http_body_util::Full;

  async fn build_request() -> anyhow::Result<Request<Full<bytes::Bytes>>> {
    let body = Full::new(&b"{\"hello\": \"world\"}"[..]);
    let req = Request::builder()
      .method("GET")
      .uri("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")
      .header("date", "Sun, 09 May 2021 18:30:00 GMT")
      .header("content-type", "application/json")
      .header("content-type", "application/json-patch+json")
      .body(body)
      .unwrap();
    req.set_content_digest(&ContentDigestType::Sha256).await
  }

  #[tokio::test]
  async fn test_extract_component_from_request() {
    let req = build_request().await.unwrap();

    let component_id_method = HttpMessageComponentId::try_from("\"@method\"").unwrap();
    let component = extract_http_message_component_from_request(&req, &component_id_method).unwrap();
    assert_eq!(component.to_string(), "\"@method\": GET");

    let component_id = HttpMessageComponentId::try_from("\"date\"").unwrap();
    let component = extract_http_message_component_from_request(&req, &component_id).unwrap();
    assert_eq!(component.to_string(), "\"date\": Sun, 09 May 2021 18:30:00 GMT");

    let component_id = HttpMessageComponentId::try_from("content-type").unwrap();
    let component = extract_http_field_from_request(&req, &component_id).unwrap();
    assert_eq!(
      component.to_string(),
      "\"content-type\": application/json, application/json-patch+json"
    );

    let component_id = HttpMessageComponentId::try_from("content-digest").unwrap();
    let component = extract_http_message_component_from_request(&req, &component_id).unwrap();
    assert_eq!(
      component.to_string(),
      "\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
    );
  }

  #[tokio::test]
  async fn test_extract_signature_params_from_request() {
    let mut req = build_request().await.unwrap();
    let headers = req.headers_mut();
    headers.insert(
      "signature-input",
      http::HeaderValue::from_static(r##"sig1=("@method" "@authority")"##),
    );
    let component_id = HttpMessageComponentId::try_from("@signature-params").unwrap();
    let component = extract_http_message_component_from_request(&req, &component_id).unwrap();
    assert_eq!(component.to_string(), "\"@signature-params\": (\"@method\" \"@authority\")");
    assert_eq!(component.value.to_string(), r##"("@method" "@authority")"##);
    assert_eq!(component.value.as_field_value(), r##"sig1=("@method" "@authority")"##);
    assert_eq!(component.value.as_component_value(), r##"("@method" "@authority")"##);
    assert_eq!(component.value.key(), Some("sig1"));
  }

  #[tokio::test]
  async fn test_build_signature_base_from_request() {
    let req = build_request().await.unwrap();

    const SIGPARA: &str = r##";created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is""##;
    let values = (r##""@method" "content-type" "date" "content-digest""##, SIGPARA);
    let signature_params = HttpSignatureParams::try_from(format!("({}){}", values.0, values.1).as_str()).unwrap();

    let signature_base = build_signature_base_from_request(&req, &signature_params).unwrap();
    assert_eq!(
      signature_base.to_string(),
      r##""@method": GET
"content-type": application/json, application/json-patch+json
"date": Sun, 09 May 2021 18:30:00 GMT
"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
"@signature-params": ("@method" "content-type" "date" "content-digest");created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is""##
    );
  }
}
