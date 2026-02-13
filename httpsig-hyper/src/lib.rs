//! # httpsig-hyper
//!
//! `httpsig-hyper` is a crate that provides a convenient API for `Hyper` users to handle HTTP signatures.
//! This crate extends hyper's http request and response messages with the ability to generate and verify HTTP signatures.
//! Additionally it also provides a way to set and verify content-digest header.
//!
//! ## Async-first design
//!
//! The primary API is fully async, allowing concurrent processing of multiple signatures via
//! [`MessageSignatureReq`] and [`MessageSignatureRes`].
//!
//! ## Blocking API
//!
//! When the `blocking` feature is enabled (on by default), synchronous wrappers are provided via
//! [`MessageSignatureReqSync`] and [`MessageSignatureResSync`]. These use `futures::executor::block_on`
//! internally and are intended **exclusively for non-async contexts**.
//!
//! # Panics
//!
//! Calling any `*_sync` method from within an async runtime (e.g. inside a `tokio::spawn` task)
//! will panic. If you are already in an async context, use the async methods directly.

mod error;
mod hyper_content_digest;
mod hyper_http;

// hyper's http specific extension to generate and verify http signature

/// content-digest header name
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

impl std::str::FromStr for ContentDigestType {
  type Err = error::HyperDigestError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "sha-256" => Ok(ContentDigestType::Sha256),
      "sha-512" => Ok(ContentDigestType::Sha512),
      _ => Err(error::HyperDigestError::InvalidContentDigestType(s.to_string())),
    }
  }
}

pub use error::{HyperDigestError, HyperDigestResult, HyperSigError, HyperSigResult};
pub use httpsig::prelude;
pub use hyper_content_digest::{ContentDigest, RequestContentDigest, ResponseContentDigest};
pub use hyper_http::{
  MessageSignature, MessageSignatureReq, MessageSignatureReqSync, MessageSignatureRes, MessageSignatureResSync,
};

/* ----------------------------------------------------------------- */
#[cfg(test)]
mod tests {
  use super::{prelude::*, *};
  use http::{Request, Response};
  use http_body_util::Full;
  use httpsig::prelude::{PublicKey, SecretKey};

  type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, crate::error::HyperDigestError>;

  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
  // const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is";

  const COVERED_COMPONENTS_REQ: &[&str] = &["@method", "date", "content-type", "content-digest"];
  const COVERED_COMPONENTS_RES: &[&str] = &["@status", "\"@method\";req", "date", "content-type", "\"content-digest\";req"];

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

  async fn build_response() -> Response<BoxBody> {
    let body = Full::new(&b"{\"hello\": \"world!!\"}"[..]);
    let res = Response::builder()
      .status(200)
      .header("date", "Sun, 09 May 2021 18:30:00 GMT")
      .header("content-type", "application/json")
      .header("content-type", "application/json-patch+json")
      .body(body)
      .unwrap();
    res.set_content_digest(&ContentDigestType::Sha256).await.unwrap()
  }

  #[test]
  fn test_content_digest_type() {
    assert_eq!(ContentDigestType::Sha256.to_string(), "sha-256");
    assert_eq!(ContentDigestType::Sha512.to_string(), "sha-512");
  }

  #[tokio::test]
  async fn test_set_verify_request() {
    // show usage of set_message_signature and verify_message_signature

    let mut req = build_request().await;

    let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();

    let covered_components = COVERED_COMPONENTS_REQ
      .iter()
      .map(|v| message_component::HttpMessageComponentId::try_from(*v))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

    // set key information, alg and keyid
    signature_params.set_key_info(&secret_key);

    // set custom signature name
    req
      .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"))
      .await
      .unwrap();
    let signature_input = req.headers().get("signature-input").unwrap().to_str().unwrap();
    let signature = req.headers().get("signature").unwrap().to_str().unwrap();
    assert!(signature_input.starts_with(r##"custom_sig_name=("##));
    assert!(signature.starts_with(r##"custom_sig_name=:"##));

    // verify without checking key_id
    // get algorithm from signature params
    let (alg, _key_id) = req.get_alg_key_ids().unwrap().into_iter().next().unwrap().1;
    let public_key = PublicKey::from_pem(&alg.unwrap(), EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = req.verify_message_signature(&public_key, None).await;
    assert!(verification_res.is_ok());

    // verify with checking key_id
    let key_id = public_key.key_id();
    let verification_res = req.verify_message_signature(&public_key, Some(&key_id)).await;
    assert!(verification_res.is_ok());

    let verification_res = req.verify_message_signature(&public_key, Some("NotFoundKeyId")).await;
    assert!(verification_res.is_err());
  }

  #[tokio::test]
  async fn test_set_verify_response() {
    // show usage of set_message_signature and verify_message_signature

    let req = build_request().await;
    let mut res = build_response().await;

    let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();

    let covered_components = COVERED_COMPONENTS_RES
      .iter()
      .map(|v| message_component::HttpMessageComponentId::try_from(*v))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

    // set key information, alg and keyid
    signature_params.set_key_info(&secret_key);

    // set custom signature name, and `req` field param if needed (e.g., request method, uri, content-digest, etc.) included only in response
    res
      .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"), Some(&req))
      .await
      .unwrap();
    let signature_input = res.headers().get("signature-input").unwrap().to_str().unwrap();
    let signature = res.headers().get("signature").unwrap().to_str().unwrap();
    assert!(signature_input.starts_with(r##"custom_sig_name=("##));
    assert!(signature.starts_with(r##"custom_sig_name=:"##));

    // verify without checking key_id, request must be provided if `req` field param is included in signature params
    // get algorithm from signature params
    let (alg, _key_id) = res.get_alg_key_ids().unwrap().into_iter().next().unwrap().1;
    let public_key = PublicKey::from_pem(&alg.unwrap(), EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = res.verify_message_signature(&public_key, None, Some(&req)).await;
    assert!(verification_res.is_ok());
    let verification_res = res
      .verify_message_signature(&public_key, None, None as Option<&Request<()>>)
      .await;
    assert!(verification_res.is_err());

    // verify with checking key_id
    let key_id = public_key.key_id();
    let verification_res = res.verify_message_signature(&public_key, Some(&key_id), Some(&req)).await;
    assert!(verification_res.is_ok());

    let verification_res = res
      .verify_message_signature(&public_key, Some("NotFoundKeyId"), Some(&req))
      .await;
    assert!(verification_res.is_err());
  }

  #[cfg(feature = "blocking")]
  #[test]
  fn test_set_verify_request_sync() {
    // show usage of set_message_signature_sync and verify_message_signature_sync

    let mut req = futures::executor::block_on(build_request());
    let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
    let covered_components = COVERED_COMPONENTS_REQ
      .iter()
      .map(|v| message_component::HttpMessageComponentId::try_from(*v))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();
    // set key information, alg and keyid
    signature_params.set_key_info(&secret_key);
    // set signature
    req.set_message_signature_sync(&signature_params, &secret_key, None).unwrap();

    let (alg, _key_id) = req.get_alg_key_ids().unwrap().into_iter().next().unwrap().1;
    let public_key = PublicKey::from_pem(&alg.unwrap(), EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = req.verify_message_signature_sync(&public_key, None);
    assert!(verification_res.is_ok());
  }

  #[cfg(feature = "blocking")]
  #[test]
  fn test_set_verify_response_sync() {
    // show usage of set_message_signature_sync and verify_message_signature_sync
    let req = futures::executor::block_on(build_request());
    let mut res = futures::executor::block_on(build_response());
    let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
    let covered_components = COVERED_COMPONENTS_RES
      .iter()
      .map(|v| message_component::HttpMessageComponentId::try_from(*v))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();
    // set key information, alg and keyid
    signature_params.set_key_info(&secret_key);
    // set signature
    res
      .set_message_signature_sync(&signature_params, &secret_key, None, Some(&req))
      .unwrap();

    let (alg, _key_id) = res.get_alg_key_ids().unwrap().into_iter().next().unwrap().1;
    let public_key = PublicKey::from_pem(&alg.unwrap(), EDDSA_PUBLIC_KEY).unwrap();
    let verification_res = res.verify_message_signature_sync(&public_key, None, Some(&req));
    assert!(verification_res.is_ok());
  }
}
