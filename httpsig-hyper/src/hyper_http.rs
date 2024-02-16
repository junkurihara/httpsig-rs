use crate::error::{HyperSigError, HyperSigResult};
use http::Request;
use http_body::Body;
use httpsig::prelude::{
  message_component::{
    DerivedComponentName, HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName, HttpMessageComponentParam,
  },
  HttpSignatureBase, HttpSignatureHeaders, HttpSignatureParams, SigningKey, VerifyingKey,
};
use std::future::Future;

type IndexMap<K, V> = indexmap::IndexMap<K, V, fxhash::FxBuildHasher>;

/* --------------------------------------- */
/// A trait to set the http message signature from given http signature params
pub trait RequestMessageSignature {
  type Error;

  /// Set the http message signature from given http signature params and signing key
  fn set_message_signature<T>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> impl Future<Output = Result<(), Self::Error>> + Send
  where
    Self: Sized,
    T: SigningKey + Sync;

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  fn verify_message_signature<T>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
  ) -> impl Future<Output = Result<(), Self::Error>> + Send
  where
    Self: Sized,
    T: VerifyingKey + Sync;

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool;
}

impl<D> RequestMessageSignature for Request<D>
where
  D: Send + Body + Sync,
{
  type Error = HyperSigError;

  /// Set the http message signature from given http signature params and signing key
  async fn set_message_signature<T>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> HyperSigResult<()>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    let signature_base = build_signature_base_from_request(self, signature_params)?;
    let signature_headers = signature_base.build_signature_headers(signing_key, signature_name)?;

    self
      .headers_mut()
      .append("signature-input", signature_headers.signature_input_header_value().parse()?);
    self
      .headers_mut()
      .append("signature", signature_headers.signature_header_value().parse()?);

    Ok(())
  }

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  /// Return Ok(()) if the signature is valid.
  /// If invalid for the given key or error occurs (like the case where the request does not have signature and/or signature-input headers), return Err.
  /// If key_id is given, it is used to match the key id in signature params
  async fn verify_message_signature<T>(&self, verifying_key: &T, key_id: Option<&str>) -> HyperSigResult<()>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    if !self.has_message_signature() {
      return Err(HyperSigError::NoSignatureHeaders(
        "The request does not have signature and signature-input headers".to_string(),
      ));
    }

    let signature_headers_map = extract_signature_headers_with_name(self)?;

    // filter by key_id if given
    let filtered = if let Some(key_id) = key_id {
      signature_headers_map
        .into_iter()
        .filter(|tuple| {
          let params_keyid = tuple.1.signature_params().keyid.as_ref();
          params_keyid.is_some() && params_keyid.unwrap() == key_id
        })
        .collect::<IndexMap<_, _>>()
    } else {
      signature_headers_map
    };
    if filtered.is_empty() {
      return Err(HyperSigError::NoSignatureHeaders(
        "No signature as appropriate target for verification".to_string(),
      ));
    }

    // check if any one of the signature headers is valid
    let res = filtered
      .iter()
      .map(|(_, headers)| {
        let signature_base = build_signature_base_from_request(self, headers.signature_params())?;
        signature_base
          .verify_signature_headers(verifying_key, headers)
          .map_err(|e| e.into()) as HyperSigResult<()>
      })
      .any(|r| r.is_ok());

    if res {
      Ok(())
    } else {
      Err(HyperSigError::InvalidSignature(
        "Invalid signature for the verifying key".to_string(),
      ))
    }
  }

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool {
    self.headers().contains_key("signature") && self.headers().contains_key("signature-input")
  }
}

/* --------------------------------------- */
#[allow(unused)]
struct SignatureTuple {
  name: String,
  signature_params: HttpSignatureParams,
  signature: Vec<u8>,
}
/// Extract signature and signature-input with signature-name indication from http request
fn extract_signature_headers_with_name<B>(req: &Request<B>) -> HyperSigResult<IndexMap<String, HttpSignatureHeaders>> {
  if !(req.headers().contains_key("signature-input") && req.headers().contains_key("signature")) {
    return Err(HyperSigError::NoSignatureHeaders(
      "The request does not have signature and signature-input headers".to_string(),
    ));
  };

  let signature_input_strings = req
    .headers()
    .get_all("signature-input")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()?
    .join(", ");
  let signature_strings = req
    .headers()
    .get_all("signature")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()?
    .join(", ");

  let signature_headers = HttpSignatureHeaders::try_parse(&signature_strings, &signature_input_strings)?;
  Ok(signature_headers)
}

/// Build signature base from hyper http request and signature params
fn build_signature_base_from_request<B>(
  req: &Request<B>,
  signature_params: &HttpSignatureParams,
) -> HyperSigResult<HttpSignatureBase> {
  let component_lines = signature_params
    .covered_components
    .iter()
    .map(|component_id| extract_http_message_component_from_request(req, component_id))
    .collect::<Result<Vec<_>, _>>()?;

  HttpSignatureBase::try_new(&component_lines, signature_params).map_err(|e| e.into())
}

/// Extract http field from hyper http request
fn extract_http_field_from_request<B>(req: &Request<B>, id: &HttpMessageComponentId) -> HyperSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::HttpField(header_name) = &id.name else {
    return Err(HyperSigError::InvalidComponentName(
      "invalid http message component name as http field".to_string(),
    ));
  };
  if id.params.0.contains(&HttpMessageComponentParam::Req) {
    return Err(HyperSigError::InvalidComponentParam(
      "`req` is not allowed in request".to_string(),
    ));
  }

  let field_values = req
    .headers()
    .get_all(header_name)
    .iter()
    .map(|v| v.to_str().map(|s| s.to_owned()))
    .collect::<Result<Vec<_>, _>>()?;

  HttpMessageComponent::try_from((id, field_values.as_slice())).map_err(|e| e.into())
}

/// Extract derived component from hyper http request
fn extract_derived_component_from_request<B>(
  req: &Request<B>,
  id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::Derived(derived_id) = &id.name else {
    return Err(HyperSigError::InvalidComponentName(
      "invalid http message component name as derived component".to_string(),
    ));
  };
  if !id.params.0.is_empty() {
    return Err(HyperSigError::InvalidComponentParam(
      "derived component does not allow parameters for request".to_string(),
    ));
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
    DerivedComponentName::Status => {
      return Err(HyperSigError::InvalidComponentName(
        "`status` is only for response".to_string(),
      ))
    }
    DerivedComponentName::SignatureParams => req
      .headers()
      .get_all("signature-input")
      .iter()
      .map(|v| v.to_str().unwrap_or("").to_string())
      .collect::<Vec<_>>(),
  };

  HttpMessageComponent::try_from((id, field_values.as_slice())).map_err(|e| e.into())
}

/* --------------------------------------- */
/// Extract http message component from hyper http request
fn extract_http_message_component_from_request<B>(
  req: &Request<B>,
  target_component_id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  match &target_component_id.name {
    HttpMessageComponentName::HttpField(_) => extract_http_field_from_request(req, target_component_id),
    HttpMessageComponentName::Derived(_) => extract_derived_component_from_request(req, target_component_id),
  }
}

/* --------------------------------------- */
#[cfg(test)]
mod tests {

  use super::{
    super::{error::HyperDigestError, hyper_content_digest::RequestContentDigest, ContentDigestType},
    *,
  };
  use http_body_util::Full;
  use httpsig::prelude::{PublicKey, SecretKey, SharedKey};

  type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, HyperDigestError>;

  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
  // const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is";
  const COVERED_COMPONENTS: &[&str] = &["@method", "date", "content-type", "content-digest"];

  async fn build_request() -> Request<BoxBody> {
    let body = Full::new(&b"{\"hello\": \"world\"}"[..]);
    let req = Request::builder()
      .method("GET")
      .uri("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")
      .header("date", "Sun, 09 May 2021 18:30:00 GMT")
      .header("content-type", "application/json")
      .header("content-type", "application/json-patch+json")
      .body(body)
      .unwrap();
    req.set_content_digest(&ContentDigestType::Sha256).await.unwrap()
  }

  fn build_covered_components() -> Vec<HttpMessageComponentId> {
    COVERED_COMPONENTS
      .iter()
      .map(|&s| HttpMessageComponentId::try_from(s).unwrap())
      .collect()
  }

  #[tokio::test]
  async fn test_extract_component_from_request() {
    let req = build_request().await;

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
    let mut req = build_request().await;
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
    let req = build_request().await;

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
    let mut req = build_request().await;
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

    let tuples = extract_signature_headers_with_name(&req).unwrap();
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples.get("sig11").unwrap().signature_name(), "sig11");
    assert_eq!(
      tuples.get("sig11").unwrap().signature_params().to_string(),
      r##"("@method" "@authority");created=1704972031"##
    );
  }

  #[tokio::test]
  async fn test_set_verify_message_signature() {
    let mut req = build_request().await;
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);

    req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();
    let signature_input = req.headers().get("signature-input").unwrap().to_str().unwrap();
    assert!(signature_input.starts_with(r##"sig=("@method" "date" "content-type" "content-digest")"##));
    // let signature = req.headers().get("signature").unwrap().to_str().unwrap();

    let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = req.verify_message_signature(&public_key, None).await;
    assert!(verification_res.is_ok());
  }

  #[tokio::test]
  async fn test_set_verify_with_signature_name() {
    let mut req = build_request().await;
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);

    req
      .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"))
      .await
      .unwrap();

    let signature_headers_map = extract_signature_headers_with_name(&req).unwrap();
    assert_eq!(signature_headers_map.len(), 1);
    assert_eq!(signature_headers_map[0].signature_name(), "custom_sig_name");

    let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = req.verify_message_signature(&public_key, None).await;
    assert!(verification_res.is_ok());
  }

  #[tokio::test]
  async fn test_set_verify_with_key_id() {
    let mut req = build_request().await;
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);

    req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();

    let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let key_id = public_key.key_id();
    let verification_res = req.verify_message_signature(&public_key, Some(&key_id)).await;
    assert!(verification_res.is_ok());

    let verification_res = req.verify_message_signature(&public_key, Some("NotFoundKeyId")).await;
    assert!(verification_res.is_err());
  }

  const HMACSHA256_SECRET_KEY: &str =
    r##"uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="##;

  #[tokio::test]
  async fn test_set_verify_with_key_id_hmac_sha256() {
    let mut req = build_request().await;
    let secret_key = SharedKey::from_base64(HMACSHA256_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);
    // Random nonce is highly recommended for HMAC
    signature_params.set_random_nonce();

    req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();

    let key_id = VerifyingKey::key_id(&secret_key);
    let verification_res = req.verify_message_signature(&secret_key, Some(&key_id)).await;
    assert!(verification_res.is_ok());

    let verification_res = req.verify_message_signature(&secret_key, Some("NotFoundKeyId")).await;
    assert!(verification_res.is_err());
  }
}
