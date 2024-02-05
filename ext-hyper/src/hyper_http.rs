use anyhow::{bail, ensure};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::Request;
use http_body::Body;
use httpsig::prelude::{
  message_component::{
    build_http_message_component, DerivedComponentName, HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
    HttpMessageComponentParam,
  },
  HttpSignatureBase, HttpSignatureParams, SigningKey, VerifyingKey,
};
use rustc_hash::FxHashMap as HashMap;

/// Default signature name used to indicate signature in http header (`signature` and `signature-input`)
const DEFAULT_SIGNATURE_NAME: &str = "sig";

// hyper's http specific extension to generate and verify http signature

/* --------------------------------------- */
#[async_trait]
/// A trait to set the http message signature from given http signature params
pub trait RequestMessageSignature {
  type Error;
  async fn set_message_signature<T>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> std::result::Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync;

  async fn verify_message_signature<T>(&self, verifying_key: &T, key_id: Option<&str>) -> std::result::Result<bool, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync;

  fn has_message_signature(&self) -> bool;
}

#[async_trait]
impl<D> RequestMessageSignature for Request<D>
where
  D: Send + Body + Sync,
{
  type Error = anyhow::Error;

  /// Set the http message signature from given http signature params and signing key
  async fn set_message_signature<T>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> std::result::Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    let signature_base = build_signature_base_from_request(self, signature_params)?;
    let signature_base_bytes = signature_base.as_bytes();
    let signature = signing_key.sign(&signature_base_bytes)?;
    let base64_signature = general_purpose::STANDARD.encode(signature);
    let signature_name = signature_name.unwrap_or(DEFAULT_SIGNATURE_NAME);

    let signature_input_header_value = format!("{signature_name}={signature_params}");
    let signature_header_value = format!("{signature_name}=:{base64_signature}:");
    self
      .headers_mut()
      .append("signature-input", signature_input_header_value.parse()?);
    self.headers_mut().append("signature", signature_header_value.parse()?);

    Ok(())
  }

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  /// Return true if the signature is valid, false if invalid for the given key,
  /// and error if the request does not have signature and/or signature-input headers
  /// If key_id is given, it is used to match the key id in signature params
  async fn verify_message_signature<T>(&self, verifying_key: &T, key_id: Option<&str>) -> std::result::Result<bool, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    if !self.has_message_signature() {
      bail!("The request does not have signature and signature-input headers");
    }

    let tuples = extract_name_param_signature_tuple_from_request(self)?;

    // filter by key_id if given
    let tuples = if let Some(key_id) = key_id {
      tuples
        .into_iter()
        .filter(|tuple| {
          let params_keyid = tuple.signature_params.keyid.as_ref();
          params_keyid.is_some() && params_keyid.unwrap() == key_id
        })
        .collect::<Vec<_>>()
    } else {
      tuples
    };
    ensure!(!tuples.is_empty(), "No signature for verification");

    let mut res = tuples.iter().map(|tuple| {
      let signature_base = build_signature_base_from_request(self, &tuple.signature_params)?.as_bytes();
      verifying_key.verify(&signature_base, &tuple.signature)
    });

    Ok(res.any(|r| r.is_ok()))
  }

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool {
    self.headers().contains_key("signature") && self.headers().contains_key("signature-input")
  }
}
/* --------------------------------------- */
fn split_comma_extract_kv(s: &str) -> Vec<(&str, &str)> {
  s.split(',')
    .filter(|s| !s.is_empty())
    .map(|s| {
      let trimmed = s.trim();
      trimmed.split_once('=').unwrap_or_default()
    })
    .map(|(k, v)| (k.trim(), v.trim()))
    .collect()
}

/* --------------------------------------- */
#[allow(unused)]
struct SignatureTuple {
  name: String,
  signature_params: HttpSignatureParams,
  signature: Vec<u8>,
}
/// Extract signature and signature-input with signature-name indication from http request
fn extract_name_param_signature_tuple_from_request<B>(req: &Request<B>) -> anyhow::Result<Vec<SignatureTuple>> {
  ensure!(req.headers().contains_key("signature-input") && req.headers().contains_key("signature"));

  let signature_inputs = req
    .headers()
    .get_all("signature-input")
    .iter()
    .flat_map(|v| split_comma_extract_kv(v.to_str().unwrap_or("")))
    .map(|(k, v)| {
      println!("{}, {}", k, v);
      ensure!(!v.is_empty(), "invalid signature-input format");
      let v = HttpSignatureParams::try_from(v);
      println!("{:?}", v);
      let v = v?;
      Ok((k, v)) as Result<(&str, HttpSignatureParams), anyhow::Error>
    })
    .filter_map(|r| r.ok())
    .collect::<HashMap<_, _>>();

  let signatures = req
    .headers()
    .get_all("signature")
    .iter()
    .flat_map(|v| split_comma_extract_kv(v.to_str().unwrap_or("")))
    .map(|(k, v)| {
      ensure!(
        !v.is_empty() && v.starts_with(':') && v.ends_with(':'),
        "invalid signature format"
      );
      let v = general_purpose::STANDARD.decode(&v[1..v.len() - 1])?;
      Ok((k, v)) as Result<_, anyhow::Error>
    })
    .filter_map(|r| r.ok())
    .collect::<HashMap<_, _>>();

  ensure!(
    signature_inputs.len() == signatures.len(),
    "signature and signature-input count mismatch"
  );
  ensure!(
    signature_inputs.iter().all(|(key, _)| signatures.contains_key(key)),
    "signature-input and signature key mismatch"
  );

  let tuples = signature_inputs
    .iter()
    .map(|(key, signature_params)| {
      let signature: &Vec<u8> = signatures.get(key).unwrap();
      SignatureTuple {
        name: key.to_string(),
        signature_params: signature_params.clone(),
        signature: signature.clone(),
      }
    })
    .collect::<Vec<_>>();

  Ok(tuples)
}

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
  use super::{
    super::{hyper_content_digest::RequestContentDigest, ContentDigestType},
    *,
  };
  use http_body_util::Full;
  use httpsig::prelude::{PublicKey, SecretKey};

  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
  // const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is";

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

  fn build_covered_components() -> Vec<HttpMessageComponentId> {
    vec![
      HttpMessageComponentId::try_from("@method").unwrap(),
      HttpMessageComponentId::try_from("date").unwrap(),
      HttpMessageComponentId::try_from("content-type").unwrap(),
      HttpMessageComponentId::try_from("content-digest").unwrap(),
    ]
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

  #[tokio::test]
  async fn test_extract_tuples_from_request() {
    let mut req = build_request().await.unwrap();
    let headers = req.headers_mut();
    headers.insert(
      "signature-input",
      http::HeaderValue::from_static(r##"sig11=("@method" "@authority");created=1704972031"##),
    );
    headers.insert(
      "signature",
      http::HeaderValue::from_static(
        r##"sig11=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"##,
      ),
    );

    let tuples = extract_name_param_signature_tuple_from_request(&req).unwrap();
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0].name, "sig11");
    assert_eq!(
      tuples[0].signature_params.to_string(),
      r##"("@method" "@authority");created=1704972031"##
    );
    assert_eq!(tuples[0].signature.len(), 64);
  }

  #[tokio::test]
  async fn test_set_verify_message_signature() {
    let mut req = build_request().await.unwrap();
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);

    req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();
    let signature_input = req.headers().get("signature-input").unwrap().to_str().unwrap();
    assert!(signature_input.starts_with(r##"sig=("@method" "date" "content-type" "content-digest")"##));
    // let signature = req.headers().get("signature").unwrap().to_str().unwrap();

    let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = req.verify_message_signature(&public_key, None).await.unwrap();
    assert!(verification_res);
  }

  #[tokio::test]
  async fn test_set_verify_with_key_id() {
    let mut req = build_request().await.unwrap();
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);

    req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();

    let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let key_id = public_key.key_id();
    let verification_res = req.verify_message_signature(&public_key, Some(&key_id)).await.unwrap();
    assert!(verification_res);

    let verification_res = req.verify_message_signature(&public_key, Some("NotFoundKeyId")).await;
    assert!(verification_res.is_err());
  }
}
