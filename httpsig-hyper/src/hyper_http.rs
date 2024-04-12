use crate::error::{HyperSigError, HyperSigResult};
use http::{HeaderMap, Request, Response};
use http_body::Body;
use httpsig::prelude::{
  message_component::{
    DerivedComponentName, HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName, HttpMessageComponentParam,
  },
  HttpSignatureBase, HttpSignatureHeaders, HttpSignatureHeadersMap, HttpSignatureParams, SigningKey, VerifyingKey,
};
use indexmap::{IndexMap, IndexSet};
use std::future::Future;

/// A type alias for the signature name
type SignatureName = String;
/// A type alias for the key id in base 64
type KeyId = String;

/* --------------------------------------- */
/// A trait to set the http message signature from given http signature params
pub trait MessageSignature {
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

  /// Set the http message signatures from given tuples of (http signature params, signing key, name)
  fn set_message_signatures<T>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
  ) -> impl Future<Output = Result<(), Self::Error>> + Send
  where
    Self: Sized,
    T: SigningKey + Sync;

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  fn verify_message_signature<T>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
  ) -> impl Future<Output = Result<SignatureName, Self::Error>> + Send
  where
    Self: Sized,
    T: VerifyingKey + Sync;

  /// Verify multiple signatures at once
  fn verify_message_signatures<T>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
  ) -> impl Future<Output = Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>> + Send
  where
    Self: Sized,
    T: VerifyingKey + Sync;

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool;

  /// Extract all key ids for signature bases contained in the request headers
  fn get_key_ids(&self) -> Result<IndexMap<SignatureName, KeyId>, Self::Error>;

  /// Extract all signature params used to generate signature bases contained in the request headers
  fn get_signature_params(&self) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error>;

  /// Extract all signature bases contained in the request headers
  fn extract_signatures(&self) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>, Self::Error>;
}

/* --------------------------------------- */
impl<D> MessageSignature for Request<D>
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
    self
      .set_message_signatures(&[(&signature_params, signing_key, signature_name)])
      .await
  }

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  /// Return Ok(()) if the signature is valid.
  /// If invalid for the given key or error occurs (like the case where the request does not have signature and/or signature-input headers), return Err.
  /// If key_id is given, it is used to match the key id in signature params
  async fn verify_message_signature<T>(&self, verifying_key: &T, key_id: Option<&str>) -> HyperSigResult<SignatureName>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    self
      .verify_message_signatures(&[(verifying_key, key_id)])
      .await?
      .pop()
      .unwrap()
  }

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool {
    self.headers().contains_key("signature") && self.headers().contains_key("signature-input")
  }

  /// Extract all signature bases contained in the request headers
  fn get_key_ids(&self) -> HyperSigResult<IndexMap<SignatureName, KeyId>> {
    let signature_headers_map = extract_signature_headers_with_name(self)?;
    let res = signature_headers_map
      .iter()
      .filter_map(|(name, headers)| headers.signature_params().keyid.clone().map(|key_id| (name.clone(), key_id)))
      .collect();
    Ok(res)
  }

  /// Extract all signature params used to generate signature bases contained in the request headers
  fn get_signature_params(&self) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error> {
    let signature_headers_map = extract_signature_headers_with_name(self)?;
    let res = signature_headers_map
      .iter()
      .map(|(name, headers)| (name.clone(), headers.signature_params().clone()))
      .collect();
    Ok(res)
  }

  /// Extract all signature bases contained in the request headers
  fn extract_signatures(&self) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>, Self::Error> {
    let signature_headers_map = extract_signature_headers_with_name(self)?;
    let extracted = signature_headers_map
      .iter()
      .filter_map(|(name, headers)| {
        let req_or_res = RequestOrResponse::Request(self);
        build_signature_base(&req_or_res, headers.signature_params(), None)
          .ok()
          .map(|base| (name.clone(), (base, headers.clone())))
      })
      .collect();
    Ok(extracted)
  }

  async fn set_message_signatures<T>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    let vec_signature_headers_fut = params_key_name.iter().flat_map(|(params, key, name)| {
      let req_or_res = RequestOrResponse::Request(self);
      build_signature_base(&req_or_res, params, None).map(|base| async move { base.build_signature_headers(*key, *name) })
    });
    let vec_signature_headers = futures::future::join_all(vec_signature_headers_fut)
      .await
      .into_iter()
      .collect::<Result<Vec<_>, _>>()?;
    vec_signature_headers.iter().try_for_each(|headers| {
      self
        .headers_mut()
        .append("signature-input", headers.signature_input_header_value().parse()?);
      self
        .headers_mut()
        .append("signature", headers.signature_header_value().parse()?);
      Ok(()) as Result<(), HyperSigError>
    })
  }

  async fn verify_message_signatures<T>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    if !self.has_message_signature() {
      return Err(HyperSigError::NoSignatureHeaders(
        "The request does not have signature and signature-input headers".to_string(),
      ));
    }
    let map_signature_with_base = self.extract_signatures()?;

    // verify for each key_and_id tuple
    let res_fut = key_and_id.iter().map(|(key, key_id)| {
      let filtered = if let Some(key_id) = key_id {
        map_signature_with_base
          .iter()
          .filter(|(_, (base, _))| base.keyid() == Some(key_id))
          .collect::<IndexMap<_, _>>()
      } else {
        map_signature_with_base.iter().collect()
      };

      // check if any one of the signature headers is valid in async manner
      async move {
        if filtered.is_empty() {
          return Err(HyperSigError::NoSignatureHeaders(
            "No signature as appropriate target for verification".to_string(),
          ));
        }
        // check if any one of the signature headers is valid
        let successful_sig_names = filtered
          .iter()
          .filter_map(|(&name, (base, headers))| base.verify_signature_headers(*key, headers).ok().map(|_| name.clone()))
          .collect::<IndexSet<_>>();
        if !successful_sig_names.is_empty() {
          Ok(successful_sig_names.first().unwrap().clone())
        } else {
          Err(HyperSigError::InvalidSignature(
            "Invalid signature for the verifying key".to_string(),
          ))
        }
      }
    });
    let res = futures::future::join_all(res_fut).await;
    Ok(res)
  }
}

/* --------------------------------------- */
impl<D> MessageSignature for Response<D>
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
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    self
      .set_message_signatures(&[(&signature_params, signing_key, signature_name)])
      .await
  }

  async fn set_message_signatures<T>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    todo!()
    // let vec_signature_headers_fut = params_key_name.iter().flat_map(|(params, key, name)| {
    //   build_signature_base_from_response(self, params).map(|base| async move { base.build_signature_headers(*key, *name) })
    // });
    // let vec_signature_headers = futures::future::join_all(vec_signature_headers_fut)
    //   .await
    //   .into_iter()
    //   .collect::<Result<Vec<_>, _>>()?;
    // vec_signature_headers.iter().try_for_each(|headers| {
    //   self
    //     .headers_mut()
    //     .append("signature-input", headers.signature_input_header_value().parse()?);
    //   self
    //     .headers_mut()
    //     .append("signature", headers.signature_header_value().parse()?);
    //   Ok(()) as Result<(), HyperSigError>
    // })
  }

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  /// Return Ok(()) if the signature is valid.
  /// If invalid for the given key or error occurs (like the case where the request does not have signature and/or signature-input headers), return Err.
  /// If key_id is given, it is used to match the key id in signature params
  async fn verify_message_signature<T>(&self, verifying_key: &T, key_id: Option<&str>) -> Result<SignatureName, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    self
      .verify_message_signatures(&[(verifying_key, key_id)])
      .await?
      .pop()
      .unwrap()
  }

  async fn verify_message_signatures<T>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    todo!()
  }

  fn has_message_signature(&self) -> bool {
    todo!()
  }

  fn get_key_ids(&self) -> Result<IndexMap<SignatureName, KeyId>, Self::Error> {
    todo!()
  }

  fn get_signature_params(&self) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error> {
    todo!()
  }

  fn extract_signatures(&self) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>, Self::Error> {
    todo!()
  }
}

/* --------------------------------------- */

/// A type to represent either http request or response
enum RequestOrResponse<'a, B> {
  Request(&'a Request<B>),
  Response(&'a Response<B>),
}

impl<'a, B> RequestOrResponse<'a, B> {
  fn method(&self) -> HyperSigResult<&http::Method> {
    match self {
      RequestOrResponse::Request(req) => Ok(req.method()),
      _ => Err(HyperSigError::InvalidComponentName(
        "`method` is only for request".to_string(),
      )),
    }
  }

  fn uri(&self) -> HyperSigResult<&http::Uri> {
    match self {
      RequestOrResponse::Request(req) => Ok(req.uri()),
      _ => Err(HyperSigError::InvalidComponentName("`uri` is only for request".to_string())),
    }
  }

  fn headers(&self) -> &HeaderMap {
    match self {
      RequestOrResponse::Request(req) => req.headers(),
      RequestOrResponse::Response(res) => res.headers(),
    }
  }
}

/// Extract signature and signature-input with signature-name indication from http request
fn extract_signature_headers_with_name<B>(req: &Request<B>) -> HyperSigResult<HttpSignatureHeadersMap> {
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

/// Build signature base from hyper http request/response and signature params
/// - req_or_res: the hyper http request or response
/// - signature_params: the http signature params
/// - req_for_param: corresponding request to be considered in the signature base in response
fn build_signature_base<B>(
  req_or_res: &RequestOrResponse<B>,
  signature_params: &HttpSignatureParams,
  req_for_param: Option<&Request<B>>,
) -> HyperSigResult<HttpSignatureBase> {
  let component_lines = signature_params
    .covered_components
    .iter()
    .map(|component_id| {
      if component_id.params.0.contains(&HttpMessageComponentParam::Req) {
        if matches!(req_or_res, RequestOrResponse::Request(_)) {
          return Err(HyperSigError::InvalidComponentParam(
            "`req` is not allowed in request".to_string(),
          ));
        }
        if req_for_param.is_none() {
          return Err(HyperSigError::InvalidComponentParam(
            "`req` is required for the param".to_string(),
          ));
        }
        let req = RequestOrResponse::Request(req_for_param.unwrap());
        extract_http_message_component(&req, component_id)
      } else {
        extract_http_message_component(req_or_res, component_id)
      }
    })
    .collect::<Result<Vec<_>, _>>()?;

  HttpSignatureBase::try_new(&component_lines, signature_params).map_err(|e| e.into())
}

/// Extract http field from hyper http request/response
fn extract_http_field<B>(req_or_res: &RequestOrResponse<B>, id: &HttpMessageComponentId) -> HyperSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::HttpField(header_name) = &id.name else {
    return Err(HyperSigError::InvalidComponentName(
      "invalid http message component name as http field".to_string(),
    ));
  };
  let headers = match req_or_res {
    RequestOrResponse::Request(req) => req.headers(),
    RequestOrResponse::Response(res) => res.headers(),
  };

  let field_values = headers
    .get_all(header_name)
    .iter()
    .map(|v| v.to_str().map(|s| s.to_owned()))
    .collect::<Result<Vec<_>, _>>()?;

  HttpMessageComponent::try_from((id, field_values.as_slice())).map_err(|e| e.into())
}

/// Extract derived component from hyper http request/response
fn extract_derived_component<B>(
  req_or_res: &RequestOrResponse<B>,
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
    DerivedComponentName::Method => vec![req_or_res.method()?.as_str().to_string()],
    DerivedComponentName::TargetUri => vec![req_or_res.uri()?.to_string()],
    DerivedComponentName::Authority => vec![req_or_res.uri()?.authority().map(|s| s.to_string()).unwrap_or("".to_string())],
    DerivedComponentName::Scheme => vec![req_or_res.uri()?.scheme_str().unwrap_or("").to_string()],
    DerivedComponentName::RequestTarget => match *req_or_res.method()? {
      http::Method::CONNECT => vec![req_or_res.uri()?.authority().map(|s| s.to_string()).unwrap_or("".to_string())],
      http::Method::OPTIONS => vec!["*".to_string()],
      _ => vec![req_or_res
        .uri()?
        .path_and_query()
        .map(|s| s.to_string())
        .unwrap_or("".to_string())],
    },
    DerivedComponentName::Path => vec![{
      let p = req_or_res.uri()?.path();
      if p.is_empty() {
        "/".to_string()
      } else {
        p.to_string()
      }
    }],
    DerivedComponentName::Query => vec![req_or_res.uri()?.query().map(|v| format!("?{v}")).unwrap_or("?".to_string())],
    DerivedComponentName::QueryParam => {
      let query = req_or_res.uri()?.query().unwrap_or("");
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
    DerivedComponentName::SignatureParams => req_or_res
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
fn extract_http_message_component<B>(
  req_or_res: &RequestOrResponse<B>,
  target_component_id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  match &target_component_id.name {
    HttpMessageComponentName::HttpField(_) => extract_http_field(req_or_res, target_component_id),
    HttpMessageComponentName::Derived(_) => extract_derived_component(req_or_res, target_component_id),
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
  // const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=";
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
    let req_or_res = RequestOrResponse::Request(&req);

    let component_id_method = HttpMessageComponentId::try_from("\"@method\"").unwrap();
    let component = extract_http_message_component(&req_or_res, &component_id_method).unwrap();
    assert_eq!(component.to_string(), "\"@method\": GET");

    let component_id = HttpMessageComponentId::try_from("\"date\"").unwrap();
    let component = extract_http_message_component(&req_or_res, &component_id).unwrap();
    assert_eq!(component.to_string(), "\"date\": Sun, 09 May 2021 18:30:00 GMT");

    let component_id = HttpMessageComponentId::try_from("content-type").unwrap();
    let component = extract_http_field(&req_or_res, &component_id).unwrap();
    assert_eq!(
      component.to_string(),
      "\"content-type\": application/json, application/json-patch+json"
    );

    let component_id = HttpMessageComponentId::try_from("content-digest").unwrap();
    let component = extract_http_message_component(&req_or_res, &component_id).unwrap();
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
    let req_or_res = RequestOrResponse::Request(&req);
    let component = extract_http_message_component(&req_or_res, &component_id).unwrap();
    assert_eq!(component.to_string(), "\"@signature-params\": (\"@method\" \"@authority\")");
    assert_eq!(component.value.to_string(), r##"("@method" "@authority")"##);
    assert_eq!(component.value.as_field_value(), r##"sig1=("@method" "@authority")"##);
    assert_eq!(component.value.as_component_value(), r##"("@method" "@authority")"##);
    assert_eq!(component.value.key(), Some("sig1"));
  }

  #[tokio::test]
  async fn test_build_signature_base_from_request() {
    let req = build_request().await;

    const SIGPARA: &str = r##";created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=""##;
    let values = (r##""@method" "content-type" "date" "content-digest""##, SIGPARA);
    let signature_params = HttpSignatureParams::try_from(format!("({}){}", values.0, values.1).as_str()).unwrap();

    let req_or_res = RequestOrResponse::Request(&req);
    let signature_base = build_signature_base(&req_or_res, &signature_params, None).unwrap();
    assert_eq!(
      signature_base.to_string(),
      r##""@method": GET
"content-type": application/json, application/json-patch+json
"date": Sun, 09 May 2021 18:30:00 GMT
"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
"@signature-params": ("@method" "content-type" "date" "content-digest");created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=""##
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
  async fn test_expired_signature() {
    let mut req = build_request().await;
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);
    let created = signature_params.created.unwrap();
    signature_params.set_expires(created - 1);
    assert!(signature_params.is_expired());

    req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();

    let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = req.verify_message_signature(&public_key, None).await;
    assert!(verification_res.is_err());
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

  #[tokio::test]
  async fn test_get_key_ids() {
    let mut req = build_request().await;
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params.set_key_info(&secret_key);

    req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();
    let key_ids = req.get_key_ids().unwrap();
    assert_eq!(key_ids.len(), 1);
    assert_eq!(key_ids[0], "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=");
  }

  const P256_SECERT_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv7zxW56ojrWwmSo1
4uOdbVhUfj9Jd+5aZIB9u8gtWnihRANCAARGYsMe0CT6pIypwRvoJlLNs4+cTh2K
L7fUNb5i6WbKxkpAoO+6T3pMBG5Yw7+8NuGTvvtrZAXduA2giPxQ8zCf
-----END PRIVATE KEY-----
"##;
  const P256_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERmLDHtAk+qSMqcEb6CZSzbOPnE4d
ii+31DW+YulmysZKQKDvuk96TARuWMO/vDbhk777a2QF3bgNoIj8UPMwnw==
-----END PUBLIC KEY-----
"##;
  #[tokio::test]
  async fn test_set_verify_multiple_signatures() {
    let mut req = build_request().await;

    let secret_key_eddsa = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let mut signature_params_eddsa = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params_eddsa.set_key_info(&secret_key_eddsa);

    let secret_key_p256 = SecretKey::from_pem(P256_SECERT_KEY).unwrap();
    let mut signature_params_hmac = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    signature_params_hmac.set_key_info(&secret_key_p256);

    let params_key_name = &[
      (&signature_params_eddsa, &secret_key_eddsa, Some("eddsa_sig")),
      (&signature_params_hmac, &secret_key_p256, Some("p256_sig")),
    ];

    req.set_message_signatures(params_key_name).await.unwrap();

    let public_key_eddsa = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let public_key_p256 = PublicKey::from_pem(P256_PUBLIC_KEY).unwrap();
    let key_id_eddsa = public_key_eddsa.key_id();
    let key_id_p256 = public_key_p256.key_id();

    let verification_res = req
      .verify_message_signatures(&[
        (&public_key_eddsa, Some(&key_id_eddsa)),
        (&public_key_p256, Some(&key_id_p256)),
      ])
      .await
      .unwrap();

    assert!(verification_res.len() == 2 && verification_res.iter().all(|r| r.is_ok()));
    assert!(verification_res[0].as_ref().unwrap() == "eddsa_sig");
    assert!(verification_res[1].as_ref().unwrap() == "p256_sig");
  }
}
