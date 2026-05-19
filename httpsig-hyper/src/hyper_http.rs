use crate::error::{HyperSigError, HyperSigResult};
use http::{HeaderMap, Request, Response};
use http_body::Body;
use httpsig::prelude::{
  message_component::{
    DerivedComponentName, HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
    HttpMessageComponentParam,
  },
  AlgorithmName, HttpSignatureBase, HttpSignatureHeaders, HttpSignatureHeadersMap,
  HttpSignatureParams, SigningKey, VerifyingKey,
};
use indexmap::{IndexMap, IndexSet};
use std::{borrow::Cow, future::Future, str::FromStr};

/// A type alias for the signature name
type SignatureName = String;
/// A type alias for the key id in base 64
type KeyId = String;

/* --------------------------------------- */
/// A trait about the http message signature common to both request and response
pub trait MessageSignature {
  type Error;

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool;

  /// Extract all key ids for signature bases contained in the request headers
  fn get_alg_key_ids(
    &self,
  ) -> Result<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>, Self::Error>;

  /// Extract all signature params used to generate signature bases contained in the request headers
  fn get_signature_params(
    &self,
  ) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error>;
}

/// A trait about http message signature for request
pub trait MessageSignatureReq {
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

  /// Extract all signature bases contained in the request headers
  fn extract_signatures(
    &self,
  ) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>, Self::Error>;
}

/// A trait about http message signature for response
pub trait MessageSignatureRes {
  type Error;
  /// Set the http message signature from given http signature params and signing key
  fn set_message_signature<T, B>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> impl Future<Output = Result<(), Self::Error>> + Send
  where
    Self: Sized,
    T: SigningKey + Sync,
    B: Sync;

  /// Set the http message signatures from given tuples of (http signature params, signing key, name)
  fn set_message_signatures<T, B>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> impl Future<Output = Result<(), Self::Error>> + Send
  where
    Self: Sized,
    T: SigningKey + Sync,
    B: Sync;

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  fn verify_message_signature<T, B>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> impl Future<Output = Result<SignatureName, Self::Error>> + Send
  where
    Self: Sized,
    T: VerifyingKey + Sync,
    B: Sync;

  /// Verify multiple signatures at once
  fn verify_message_signatures<T, B>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> impl Future<Output = Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>> + Send
  where
    Self: Sized,
    T: VerifyingKey + Sync,
    B: Sync;

  /// Extract all signature bases contained in the request headers
  fn extract_signatures<B>(
    &self,
    req_for_param: Option<&Request<B>>,
  ) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>, Self::Error>;
}

/* --------------------------------------- */
#[cfg(feature = "blocking")]
/// Synchronous counterpart of [`MessageSignatureReq`].
///
/// Every method delegates to the corresponding async method via `futures::executor::block_on`.
///
/// # Panics
///
/// All methods will panic if called from within an async runtime (e.g. a `tokio` task).
/// Use the async [`MessageSignatureReq`] methods instead when you are already in an async context.
pub trait MessageSignatureReqSync: MessageSignatureReq {
  fn set_message_signature_sync<T>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync;

  fn set_message_signatures_sync<T>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync;

  fn verify_message_signature_sync<T>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
  ) -> Result<SignatureName, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync;

  fn verify_message_signatures_sync<T>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync;
}

#[cfg(feature = "blocking")]
/// Synchronous counterpart of [`MessageSignatureRes`].
///
/// Every method delegates to the corresponding async method via `futures::executor::block_on`.
///
/// # Panics
///
/// All methods will panic if called from within an async runtime (e.g. a `tokio` task).
/// Use the async [`MessageSignatureRes`] methods instead when you are already in an async context.
pub trait MessageSignatureResSync: MessageSignatureRes {
  fn set_message_signature_sync<T, B>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
    B: Sync;

  fn set_message_signatures_sync<T, B>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
    B: Sync;

  fn verify_message_signature_sync<T, B>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<SignatureName, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
    B: Sync;

  fn verify_message_signatures_sync<T, B>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
    B: Sync;
}

/* --------------------------------------- */
impl<D> MessageSignature for Request<D>
where
  D: Send + Body + Sync,
{
  type Error = HyperSigError;

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool {
    has_message_signature_inner(self.headers())
  }

  /// Extract all signature bases contained in the request headers
  fn get_alg_key_ids(
    &self,
  ) -> HyperSigResult<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>> {
    get_alg_key_ids_inner(self)
  }

  /// Extract all signature params used to generate signature bases contained in the request headers
  fn get_signature_params(
    &self,
  ) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error> {
    get_signature_params_inner(self)
  }
}

const NO_REQ_FOR_PARAM: Option<&Request<()>> = None;

impl<D> MessageSignatureReq for Request<D>
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
      .set_message_signatures(&[(signature_params, signing_key, signature_name)])
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
    for (params, key, name) in params_key_name {
      let base = build_signature_base(self, params, NO_REQ_FOR_PARAM)?;
      let headers = base.build_signature_headers(*key, *name)?;
      self.headers_mut().append(
        "signature-input",
        headers.signature_input_header_value().parse()?,
      );
      self
        .headers_mut()
        .append("signature", headers.signature_header_value().parse()?);
    }
    Ok(())
  }

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  /// Return Ok(()) if the signature is valid.
  /// If invalid for the given key or error occurs (like the case where the request does not have signature and/or signature-input headers), return Err.
  /// If key_id is given, it is used to match the key id in signature params
  async fn verify_message_signature<T>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
  ) -> HyperSigResult<SignatureName>
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
    if !self.has_message_signature() {
      return Err(HyperSigError::NoSignatureHeaders(
        "The request does not have signature and signature-input headers",
      ));
    }
    let map_signature_with_base = self.extract_signatures()?;
    Ok(verify_message_signatures_inner(&map_signature_with_base, key_and_id).await)
  }

  /// Extract all signature bases contained in the request headers
  fn extract_signatures(
    &self,
  ) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>, Self::Error> {
    extract_signatures_inner(self, None as Option<&Request<()>>)
  }
}

/* --------------------------------------- */
impl<D> MessageSignature for Response<D>
where
  D: Send + Body + Sync,
{
  type Error = HyperSigError;

  /// Check if the response has signature and signature-input headers
  fn has_message_signature(&self) -> bool {
    has_message_signature_inner(self.headers())
  }

  /// Extract all key ids for signature bases contained in the response headers
  fn get_alg_key_ids(
    &self,
  ) -> Result<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>, Self::Error> {
    get_alg_key_ids_inner(self)
  }

  /// Extract all signature params used to generate signature bases contained in the response headers
  fn get_signature_params(
    &self,
  ) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error> {
    get_signature_params_inner(self)
  }
}

impl<D> MessageSignatureRes for Response<D>
where
  D: Send + Body + Sync,
{
  type Error = HyperSigError;

  /// Set the http message signature from given http signature params and signing key
  async fn set_message_signature<T, B>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
    B: Sync,
  {
    self
      .set_message_signatures(
        &[(signature_params, signing_key, signature_name)],
        req_for_param,
      )
      .await
  }

  async fn set_message_signatures<T, B>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    for (params, key, name) in params_key_name {
      let base = build_signature_base(self, params, req_for_param)?;
      let headers = base.build_signature_headers(*key, *name)?;
      self.headers_mut().append(
        "signature-input",
        headers.signature_input_header_value().parse()?,
      );
      self
        .headers_mut()
        .append("signature", headers.signature_header_value().parse()?);
    }

    Ok(())
  }

  /// Verify the http message signature with given verifying key if the response has signature and signature-input headers
  /// Return Ok(()) if the signature is valid.
  /// If invalid for the given key or error occurs (like the case where the request does not have signature and/or signature-input headers), return Err.
  /// If key_id is given, it is used to match the key id in signature params
  async fn verify_message_signature<T, B>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<SignatureName, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
    B: Sync,
  {
    self
      .verify_message_signatures(&[(verifying_key, key_id)], req_for_param)
      .await?
      .pop()
      .unwrap()
  }

  async fn verify_message_signatures<T, B>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    if !self.has_message_signature() {
      return Err(HyperSigError::NoSignatureHeaders(
        "The response does not have signature and signature-input headers",
      ));
    }
    let map_signature_with_base = self.extract_signatures(req_for_param)?;
    Ok(verify_message_signatures_inner(&map_signature_with_base, key_and_id).await)
  }

  /// Extract all signature bases contained in the response headers
  fn extract_signatures<B>(
    &self,
    req_for_param: Option<&Request<B>>,
  ) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>, Self::Error> {
    extract_signatures_inner(self, req_for_param)
  }
}

/* --------------------------------------- */
#[cfg(feature = "blocking")]
impl<D> MessageSignatureReqSync for Request<D>
where
  D: Send + Body + Sync,
{
  fn set_message_signature_sync<T>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    futures::executor::block_on(self.set_message_signature(
      signature_params,
      signing_key,
      signature_name,
    ))
  }

  fn set_message_signatures_sync<T>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
  {
    futures::executor::block_on(self.set_message_signatures(params_key_name))
  }

  fn verify_message_signature_sync<T>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
  ) -> Result<SignatureName, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    futures::executor::block_on(self.verify_message_signature(verifying_key, key_id))
  }

  fn verify_message_signatures_sync<T>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
  {
    futures::executor::block_on(self.verify_message_signatures(key_and_id))
  }
}

#[cfg(feature = "blocking")]
impl<D> MessageSignatureResSync for Response<D>
where
  D: Send + Body + Sync,
{
  fn set_message_signature_sync<T, B>(
    &mut self,
    signature_params: &HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
    B: Sync,
  {
    futures::executor::block_on(self.set_message_signature(
      signature_params,
      signing_key,
      signature_name,
      req_for_param,
    ))
  }

  fn set_message_signatures_sync<T, B>(
    &mut self,
    params_key_name: &[(&HttpSignatureParams, &T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    Self: Sized,
    T: SigningKey + Sync,
    B: Sync,
  {
    futures::executor::block_on(self.set_message_signatures(params_key_name, req_for_param))
  }

  fn verify_message_signature_sync<T, B>(
    &self,
    verifying_key: &T,
    key_id: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<SignatureName, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
    B: Sync,
  {
    futures::executor::block_on(self.verify_message_signature(verifying_key, key_id, req_for_param))
  }

  fn verify_message_signatures_sync<T, B>(
    &self,
    key_and_id: &[(&T, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    Self: Sized,
    T: VerifyingKey + Sync,
    B: Sync,
  {
    futures::executor::block_on(self.verify_message_signatures(key_and_id, req_for_param))
  }
}

/* --------------------------------------- */
// inner functions
/// has message signature inner function
fn has_message_signature_inner(headers: &HeaderMap) -> bool {
  headers.contains_key("signature") && headers.contains_key("signature-input")
}

/// get key ids inner function
fn get_alg_key_ids_inner<M: HttpMessage>(
  req_or_res: &M,
) -> HyperSigResult<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>> {
  let signature_headers_map = extract_signature_headers_with_name(req_or_res)?;
  let res = signature_headers_map
    .iter()
    .map(|(name, headers)| {
      // Unknown or unsupported algorithm strings are mapped to None
      let alg = headers
        .signature_params()
        .alg
        .as_ref()
        .map(|a| AlgorithmName::from_str(a))
        .transpose()
        .ok()
        .flatten();
      let key_id = headers.signature_params().keyid.clone();
      (name.clone(), (alg, key_id))
    })
    .collect();
  Ok(res)
}

/// get signature params inner function
fn get_signature_params_inner<M: HttpMessage>(
  req_or_res: &M,
) -> HyperSigResult<IndexMap<SignatureName, HttpSignatureParams>> {
  let signature_headers_map = extract_signature_headers_with_name(req_or_res)?;
  let res = signature_headers_map
    .iter()
    .map(|(name, headers)| (name.clone(), headers.signature_params().clone()))
    .collect();
  Ok(res)
}

/// extract signatures inner function
fn extract_signatures_inner<M: HttpMessage, B>(
  req_or_res: &M,
  req_for_param: Option<&Request<B>>,
) -> HyperSigResult<IndexMap<SignatureName, (HttpSignatureBase, HttpSignatureHeaders)>> {
  let signature_headers_map = extract_signature_headers_with_name(req_or_res)?;
  let extracted = signature_headers_map
    .into_iter()
    .filter_map(|(name, headers)| {
      build_signature_base(req_or_res, headers.signature_params(), req_for_param)
        .ok()
        .map(|base| (name, (base, headers)))
    })
    .collect();
  Ok(extracted)
}

/// Verify multiple signatures inner function
async fn verify_message_signatures_inner<T>(
  map_signature_with_base: &IndexMap<String, (HttpSignatureBase, HttpSignatureHeaders)>,
  key_and_id: &[(&T, Option<&str>)],
) -> Vec<HyperSigResult<SignatureName>>
where
  T: VerifyingKey + Sync,
{
  // verify for each key_and_id tuple
  key_and_id
    .iter()
    .map(|(key, key_id)| {
      let filtered = if let Some(key_id) = key_id {
        map_signature_with_base
          .iter()
          .filter(|(_, (base, _))| base.keyid() == Some(key_id))
          .collect::<IndexMap<_, _>>()
      } else {
        map_signature_with_base.iter().collect()
      };

      // check if any one of the signature headers is valid in async manner
      if filtered.is_empty() {
        return Err(HyperSigError::NoSignatureHeaders(
          "No signature as appropriate target for verification",
        ));
      }
      // check if any one of the signature headers is valid
      let successful_sig_names = filtered
        .iter()
        .filter_map(|(&name, (base, headers))| {
          base
            .verify_signature_headers(*key, headers)
            .ok()
            .map(|_| name.clone())
        })
        .collect::<IndexSet<_>>();
      if !successful_sig_names.is_empty() {
        Ok(successful_sig_names.first().unwrap().clone())
      } else {
        Err(HyperSigError::InvalidSignature(
          "Invalid signature for the verifying key",
        ))
      }
    })
    .collect()
}

/* --------------------------------------- */

/// [`HttpMessage`] represents http request or response message we sign or verify.
trait HttpMessage {
  fn message_method(&self) -> HyperSigResult<&http::Method>;
  fn message_uri(&self) -> HyperSigResult<&http::Uri>;
  fn message_headers(&self) -> &HeaderMap;
  fn message_status(&self) -> HyperSigResult<http::StatusCode>;
  /// Validation callback for HTTP Message, containing a component with `req` param.
  fn on_message_component_req_param(&self, caller_provided_request: bool) -> HyperSigResult<()>;
  /// Validation callback for HTTP Message, containing a derived component with `req` param.
  fn on_message_derived_component_req_param(&self) -> HyperSigResult<()>;
  /// Validation callback for HTTP Message, containing a derived component.
  fn on_message_derived_component(
    &self,
    derived_name: &DerivedComponentName,
    component_id: &HttpMessageComponentId,
  ) -> HyperSigResult<()>;
}

impl<B> HttpMessage for Request<B> {
  fn message_method(&self) -> HyperSigResult<&http::Method> {
    Ok(self.method())
  }

  fn message_uri(&self) -> HyperSigResult<&http::Uri> {
    Ok(self.uri())
  }

  fn message_headers(&self) -> &HeaderMap {
    self.headers()
  }

  fn message_status(&self) -> HyperSigResult<http::StatusCode> {
    Err(HyperSigError::InvalidComponentName(
      "`status` is only for response".into(),
    ))
  }

  fn on_message_component_req_param(&self, _caller_provided_request: bool) -> HyperSigResult<()> {
    Err(HyperSigError::InvalidComponentParam(
      "`req` is not allowed in request".into(),
    ))
  }

  fn on_message_derived_component_req_param(&self) -> HyperSigResult<()> {
    Ok(())
  }

  fn on_message_derived_component(
    &self,
    derived_name: &DerivedComponentName,
    _component_id: &HttpMessageComponentId,
  ) -> HyperSigResult<()> {
    if matches!(derived_name, DerivedComponentName::Status) {
      Err(HyperSigError::InvalidComponentName(
        "`status` is only for response".into(),
      ))
    } else {
      Ok(())
    }
  }
}

impl<B> HttpMessage for Response<B> {
  fn message_method(&self) -> HyperSigResult<&http::Method> {
    Err(HyperSigError::InvalidComponentName(
      "`method` is only for request".into(),
    ))
  }

  fn message_uri(&self) -> HyperSigResult<&http::Uri> {
    Err(HyperSigError::InvalidComponentName(
      "`uri` is only for request".into(),
    ))
  }

  fn message_headers(&self) -> &HeaderMap {
    self.headers()
  }

  fn message_status(&self) -> HyperSigResult<http::StatusCode> {
    Ok(self.status())
  }

  fn on_message_component_req_param(&self, caller_provided_request: bool) -> HyperSigResult<()> {
    if caller_provided_request {
      Ok(())
    } else {
      Err(HyperSigError::InvalidComponentParam(
        "`req` is required for the param but no request is provided".into(),
      ))
    }
  }

  fn on_message_derived_component_req_param(&self) -> HyperSigResult<()> {
    Err(HyperSigError::InvalidComponentParam(
      "`req`-tagged component must be extracted from the source request".into(),
    ))
  }

  fn on_message_derived_component(
    &self,
    derived_name: &DerivedComponentName,
    component_id: &HttpMessageComponentId,
  ) -> HyperSigResult<()> {
    let has_req = component_id
      .params
      .0
      .contains(&HttpMessageComponentParam::Req);
    if has_req {
      // `@status` must not have `req` parameter
      if matches!(derived_name, DerivedComponentName::Status) {
        Err(HyperSigError::InvalidComponentParam(
          "`@status` does not accept `req` parameter".into(),
        ))
      } else {
        Ok(())
      }
    } else {
      // Response messages can use `@status` and `@signature-params` directly,
      // or any request-derived component with the `req` parameter (RFC 9421 §2.4).
      if !matches!(
        derived_name,
        DerivedComponentName::Status | DerivedComponentName::SignatureParams
      ) {
        Err(HyperSigError::InvalidComponentName(
          "derived components other than `@status` and `@signature-params` require `req` parameter for response".into(),
        ))
      } else {
        Ok(())
      }
    }
  }
}

/// Extract signature and signature-input with signature-name indication from http request and response
fn extract_signature_headers_with_name<M: HttpMessage>(
  req_or_res: &M,
) -> HyperSigResult<HttpSignatureHeadersMap> {
  let headers = req_or_res.message_headers();
  if !(headers.contains_key("signature-input") && headers.contains_key("signature")) {
    return Err(HyperSigError::NoSignatureHeaders(
      "The request does not have signature and signature-input headers",
    ));
  };

  let signature_input_strings = headers
    .get_all("signature-input")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()?
    .join(", ");
  let signature_strings = headers
    .get_all("signature")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()?
    .join(", ");

  let signature_headers =
    HttpSignatureHeaders::try_parse(&signature_strings, &signature_input_strings)?;
  Ok(signature_headers)
}

/// Build signature base from hyper http request/response and signature params
/// - req_or_res: the hyper http request or response
/// - signature_params: the http signature params
/// - req_for_param: corresponding request to be considered in the signature base in response
fn build_signature_base<M: HttpMessage, B>(
  req_or_res: &M,
  signature_params: &HttpSignatureParams,
  req_for_param: Option<&Request<B>>,
) -> HyperSigResult<HttpSignatureBase> {
  let caller_provided_request = req_for_param.is_some();
  let component_lines = signature_params
    .covered_components
    .iter()
    .map(|component_id| {
      if component_id
        .params
        .0
        .contains(&HttpMessageComponentParam::Req)
      {
        req_or_res.on_message_component_req_param(caller_provided_request)?;
        let req = req_for_param.expect("None case handled above");
        extract_http_message_component(req, component_id)
      } else {
        extract_http_message_component(req_or_res, component_id)
      }
    })
    .collect::<Result<Vec<_>, _>>()?;

  HttpSignatureBase::try_new(component_lines, signature_params).map_err(|e| e.into())
}

/// Extract http field from hyper http request/response
fn extract_http_field<M: HttpMessage>(
  req_or_res: &M,
  id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::HttpField(header_name) = &id.name else {
    return Err(HyperSigError::InvalidComponentName(
      "invalid http message component name as http field".into(),
    ));
  };
  let headers = req_or_res.message_headers();

  let field_values = headers
    .get_all(header_name)
    .iter()
    .map(|v| v.to_str().map(|s| s.to_owned()))
    .collect::<Result<Vec<_>, _>>()?;

  HttpMessageComponent::try_from((id, field_values)).map_err(|e| e.into())
}

/// Extract derived component from hyper http request/response
fn extract_derived_component<M: HttpMessage>(
  req_or_res: &M,
  id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::Derived(derived_name) = &id.name else {
    return Err(HyperSigError::InvalidComponentName(
      "invalid http message component name as derived component".into(),
    ));
  };
  // Validate parameters allowed on derived components (RFC 9421).
  // - `name`: only valid on `@query-param`
  // - `req`: only valid on response messages (to reference request-derived components, §2.4)
  // - `sf`, `key`, `bs`, `tr`: only valid on HTTP field components, not derived components
  id.params.0.iter().try_for_each(|param| match param {
    HttpMessageComponentParam::Name(_)
      if matches!(derived_name, DerivedComponentName::QueryParam) =>
    {
      Ok(())
    }
    HttpMessageComponentParam::Name(_) => Err(HyperSigError::InvalidComponentParam(
      "`name` parameter is only allowed for `@query-param`".into(),
    )),
    // `req` is only meaningful in response signatures (RFC 9421 §2.4).
    // `build_signature_base` already validates this and re-dispatches extraction against the
    // original request, so `req_or_res` here should always be `Request`.
    // Guard against misuse by callers that bypass `build_signature_base`.
    HttpMessageComponentParam::Req => req_or_res.on_message_derived_component_req_param(),
    _ => Err(HyperSigError::InvalidComponentParam(
      format!(
        "parameter `{}` is not allowed on derived components",
        Cow::from(param)
      )
      .into(),
    )),
  })?;

  req_or_res.on_message_derived_component(derived_name, id)?;

  let field_values: Vec<String> = match derived_name {
    DerivedComponentName::Method => vec![req_or_res.message_method()?.as_str().to_string()],
    DerivedComponentName::TargetUri => vec![req_or_res.message_uri()?.to_string()],
    DerivedComponentName::Authority => vec![req_or_res
      .message_uri()?
      .authority()
      .map(|s| s.to_string())
      .unwrap_or("".to_string())],
    DerivedComponentName::Scheme => vec![req_or_res
      .message_uri()?
      .scheme_str()
      .unwrap_or("")
      .to_string()],
    DerivedComponentName::RequestTarget => match *req_or_res.message_method()? {
      http::Method::CONNECT => vec![req_or_res
        .message_uri()?
        .authority()
        .map(|s| s.to_string())
        .unwrap_or("".to_string())],
      http::Method::OPTIONS => vec!["*".to_string()],
      _ => vec![req_or_res
        .message_uri()?
        .path_and_query()
        .map(|s| s.to_string())
        .unwrap_or("".to_string())],
    },
    DerivedComponentName::Path => vec![{
      let p = req_or_res.message_uri()?.path();
      if p.is_empty() {
        "/".to_string()
      } else {
        p.to_string()
      }
    }],
    DerivedComponentName::Query => vec![req_or_res
      .message_uri()?
      .query()
      .map(|v| format!("?{v}"))
      .unwrap_or("?".to_string())],
    DerivedComponentName::QueryParam => {
      let query = req_or_res.message_uri()?.query().unwrap_or("");
      query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    }
    DerivedComponentName::Status => vec![req_or_res.message_status()?.as_str().to_string()],
    DerivedComponentName::SignatureParams => req_or_res
      .message_headers()
      .get_all("signature-input")
      .iter()
      .map(|v| v.to_str().unwrap_or("").to_string())
      .collect::<Vec<_>>(),
  };

  HttpMessageComponent::try_from((id, field_values)).map_err(|e| e.into())
}

/* --------------------------------------- */
/// Extract http message component from hyper http request
fn extract_http_message_component<M: HttpMessage>(
  req_or_res: &M,
  target_component_id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  match &target_component_id.name {
    HttpMessageComponentName::HttpField(_) => extract_http_field(req_or_res, target_component_id),
    HttpMessageComponentName::Derived(_) => {
      extract_derived_component(req_or_res, target_component_id)
    }
  }
}

/* --------------------------------------- */
#[cfg(all(test, feature = "digest-sha256"))]
#[path = "hyper_http_tests.rs"]
mod tests;
