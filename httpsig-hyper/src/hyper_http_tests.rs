use super::{
  super::{
    error::HyperDigestError,
    hyper_content_digest::{RequestContentDigest, ResponseContentDigest},
    ContentDigestType,
  },
  *,
};
use http_body_util::{BodyExt, Full};
use httpsig::prelude::{AlgorithmName, PublicKey, SecretKey, SharedKey};

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

fn build_covered_components_req() -> Vec<HttpMessageComponentId> {
  COVERED_COMPONENTS_REQ
    .iter()
    .map(|&s| HttpMessageComponentId::try_from(s).unwrap())
    .collect()
}

fn build_covered_components_res() -> Vec<HttpMessageComponentId> {
  COVERED_COMPONENTS_RES
    .iter()
    .map(|&s| HttpMessageComponentId::try_from(s).unwrap())
    .collect()
}

/// Helper to build a request with query parameters (no content-digest needed)
fn build_query_request() -> Request<BoxBody> {
  let body = Full::new(bytes::Bytes::new()).map_err(|never| match never {}).boxed();
  Request::builder()
    .method("GET")
    .uri("https://example.com/path?foo=bar&id=123&x=y")
    .header("date", "Sun, 09 May 2021 18:30:00 GMT")
    .body(body)
    .unwrap()
}

// ---- Component extraction ----

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
  let signature_base = build_signature_base(&req_or_res, &signature_params, None as Option<&Request<()>>).unwrap();
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

  let req_or_res = RequestOrResponse::Request(&req);
  let tuples = extract_signature_headers_with_name(&req_or_res).unwrap();
  assert_eq!(tuples.len(), 1);
  assert_eq!(tuples.get("sig11").unwrap().signature_name(), "sig11");
  assert_eq!(
    tuples.get("sig11").unwrap().signature_params().to_string(),
    r##"("@method" "@authority");created=1704972031"##
  );
}

// ---- Sign and verify ----

#[tokio::test]
async fn test_set_verify_message_signature_req() {
  let mut req = build_request().await;
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&secret_key);

  req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();
  let signature_input = req.headers().get("signature-input").unwrap().to_str().unwrap();
  assert!(signature_input.starts_with(r##"sig=("@method" "date" "content-type" "content-digest")"##));

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = req.verify_message_signature(&public_key, None).await;
  assert!(verification_res.is_ok());
}

#[tokio::test]
async fn test_set_verify_message_signature_res() {
  let req = build_request().await;
  let mut res = build_response().await;

  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();

  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_res()).unwrap();
  signature_params.set_key_info(&secret_key);

  res
    .set_message_signature(&signature_params, &secret_key, None, Some(&req))
    .await
    .unwrap();
  let signature_input = res.headers().get("signature-input").unwrap().to_str().unwrap();
  assert!(signature_input.starts_with(r##"sig=("@status" "@method";req "date" "content-type" "content-digest";req)"##));

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = res.verify_message_signature(&public_key, None, Some(&req)).await;
  assert!(verification_res.is_ok());
}

#[tokio::test]
async fn test_expired_signature() {
  let mut req = build_request().await;
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&secret_key);
  let created = signature_params.created.unwrap();
  signature_params.set_expires(created - 1);
  assert!(signature_params.is_expired());

  req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = req.verify_message_signature(&public_key, None).await;
  assert!(verification_res.is_err());
}

#[tokio::test]
async fn test_set_verify_with_signature_name() {
  let mut req = build_request().await;
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&secret_key);

  req
    .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"))
    .await
    .unwrap();

  let req_or_res = RequestOrResponse::Request(&req);
  let signature_headers_map = extract_signature_headers_with_name(&req_or_res).unwrap();
  assert_eq!(signature_headers_map.len(), 1);
  assert_eq!(signature_headers_map[0].signature_name(), "custom_sig_name");

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = req.verify_message_signature(&public_key, None).await;
  assert!(verification_res.is_ok());
}

#[tokio::test]
async fn test_set_verify_with_key_id() {
  let mut req = build_request().await;
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&secret_key);

  req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
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
  let secret_key = SharedKey::from_base64(&AlgorithmName::HmacSha256, HMACSHA256_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&secret_key);
  // Random nonce is highly recommended for HMAC
  signature_params.set_random_nonce();

  req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();

  let org_key_id = VerifyingKey::key_id(&secret_key);
  let (alg, key_id) = req.get_alg_key_ids().unwrap().into_iter().next().unwrap().1;
  let alg = alg.unwrap();
  let key_id = key_id.unwrap();
  assert_eq!(org_key_id, key_id);
  let verification_key = SharedKey::from_base64(&alg, HMACSHA256_SECRET_KEY).unwrap();
  let verification_res = req.verify_message_signature(&verification_key, Some(&key_id)).await;
  assert!(verification_res.is_ok());

  let verification_res = req.verify_message_signature(&verification_key, Some("NotFoundKeyId")).await;
  assert!(verification_res.is_err());
}

#[tokio::test]
async fn test_get_alg_key_ids() {
  let mut req = build_request().await;
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&secret_key);

  req.set_message_signature(&signature_params, &secret_key, None).await.unwrap();
  let key_ids = req.get_alg_key_ids().unwrap();
  assert_eq!(key_ids.len(), 1);
  assert_eq!(key_ids[0].0.as_ref().unwrap(), &AlgorithmName::Ed25519);
  assert_eq!(key_ids[0].1.as_ref().unwrap(), "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=");
}

const P256_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
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

  let secret_key_eddsa = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params_eddsa = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params_eddsa.set_key_info(&secret_key_eddsa);

  let secret_key_p256 = SecretKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_SECRET_KEY).unwrap();
  let mut signature_params_hmac = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params_hmac.set_key_info(&secret_key_p256);

  let params_key_name = &[
    (&signature_params_eddsa, &secret_key_eddsa, Some("eddsa_sig")),
    (&signature_params_hmac, &secret_key_p256, Some("p256_sig")),
  ];

  req.set_message_signatures(params_key_name).await.unwrap();

  let public_key_eddsa = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let public_key_p256 = PublicKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_PUBLIC_KEY).unwrap();
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

// ---- Blocking (sync) ----

#[cfg(feature = "blocking")]
#[test]
fn test_blocking_set_verify_message_signature_req() {
  let mut req = futures::executor::block_on(build_request());
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&secret_key);

  req.set_message_signature_sync(&signature_params, &secret_key, None).unwrap();

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = req.verify_message_signature_sync(&public_key, None);
  assert!(verification_res.is_ok());
}

#[cfg(feature = "blocking")]
#[test]
fn test_blocking_set_verify_message_signature_res() {
  let req = futures::executor::block_on(build_request());
  let mut res = futures::executor::block_on(build_response());
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_res()).unwrap();
  signature_params.set_key_info(&secret_key);
  res
    .set_message_signature_sync(&signature_params, &secret_key, None, Some(&req))
    .unwrap();

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = res.verify_message_signature_sync(&public_key, None, Some(&req));
  assert!(verification_res.is_ok());
}

// ---- Issue #17: @query-param;name="..." ----

/// Regression test for issue #17: @query-param;name="id" must produce signature headers (sync)
#[cfg(feature = "blocking")]
#[test]
fn test_query_param_sign_verify_sync() {
  let mut req = build_query_request();

  let covered = ["@method", "\"@query-param\";name=\"id\"", "date"];
  let covered_components = covered
    .iter()
    .map(|v| HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();

  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();
  signature_params.set_key_info(&secret_key);

  req
    .set_message_signature_sync(&signature_params, &secret_key, Some("qp"))
    .unwrap();

  assert!(
    req.headers().get("signature-input").is_some(),
    "signature-input header is missing"
  );
  assert!(req.headers().get("signature").is_some(), "signature header is missing");

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = req.verify_message_signature_sync(&public_key, None);
  assert!(
    verification_res.is_ok(),
    "signature verification failed: {:?}",
    verification_res.err()
  );
}

/// Regression test for issue #17: @query-param;name="id" must produce signature headers (async)
#[tokio::test]
async fn test_query_param_sign_verify_async() {
  let mut req = build_query_request();

  let covered = ["@method", "\"@query-param\";name=\"id\"", "date"];
  let covered_components = covered
    .iter()
    .map(|v| HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();

  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();
  signature_params.set_key_info(&secret_key);

  req
    .set_message_signature(&signature_params, &secret_key, Some("qp"))
    .await
    .unwrap();

  assert!(
    req.headers().get("signature-input").is_some(),
    "signature-input header is missing"
  );
  assert!(req.headers().get("signature").is_some(), "signature header is missing");

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = req.verify_message_signature(&public_key, None).await;
  assert!(
    verification_res.is_ok(),
    "signature verification failed: {:?}",
    verification_res.err()
  );
}

// ---- Derived component parameter validation ----

#[test]
fn test_extract_derived_component_rejects_name_on_non_query_param() {
  let req = build_query_request();
  let req_or_res = RequestOrResponse::Request(&req);
  // `@method;name="foo"` is invalid — `name` is only for `@query-param`
  let id = HttpMessageComponentId::try_from("\"@method\";name=\"foo\"");
  // component_id parsing itself may reject this; if it doesn't, extraction should
  if let Ok(id) = id {
    let result = extract_derived_component(&req_or_res, &id);
    assert!(result.is_err(), "expected error for `name` on `@method`");
  }
}

#[test]
fn test_extract_derived_component_rejects_sf_on_derived() {
  let req = build_query_request();
  let req_or_res = RequestOrResponse::Request(&req);
  // `@method;sf` is invalid — `sf` is only for HTTP field components
  let id = HttpMessageComponentId::try_from("\"@method\";sf");
  if let Ok(id) = id {
    let result = extract_derived_component(&req_or_res, &id);
    assert!(result.is_err(), "expected error for `sf` on derived component");
  }
}

// ---- Error propagation (Bug #2 regression) ----

#[tokio::test]
async fn test_set_message_signature_propagates_build_error() {
  // Use `@status` on a request — this is invalid and must return Err, not Ok
  let body = Full::new(bytes::Bytes::new()).map_err(|never| match never {}).boxed();
  let mut req: Request<BoxBody> = Request::builder()
    .method("GET")
    .uri("https://example.com/")
    .body(body)
    .unwrap();

  let covered = vec![HttpMessageComponentId::try_from("@status").unwrap()];
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered).unwrap();
  signature_params.set_key_info(&secret_key);

  let result = req
    .set_message_signature(&signature_params, &secret_key, None as Option<&str>)
    .await;
  assert!(result.is_err(), "expected Err when using `@status` on request, got Ok");
}

#[cfg(feature = "blocking")]
#[test]
fn test_set_message_signature_sync_propagates_build_error() {
  // Same as above but for sync path
  let body = Full::new(bytes::Bytes::new()).map_err(|never| match never {}).boxed();
  let mut req: Request<BoxBody> = Request::builder()
    .method("GET")
    .uri("https://example.com/")
    .body(body)
    .unwrap();

  let covered = vec![HttpMessageComponentId::try_from("@status").unwrap()];
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered).unwrap();
  signature_params.set_key_info(&secret_key);

  let result = req.set_message_signature_sync(&signature_params, &secret_key, None);
  assert!(result.is_err(), "expected Err when using `@status` on request, got Ok");
}

// ---- RFC 9421 §2.2: Derived component extraction values ----

#[test]
fn test_extract_derived_components_values() {
  let req = build_query_request();
  // URI: https://example.com/path?foo=bar&id=123&x=y
  let req_or_res = RequestOrResponse::Request(&req);

  // @method (§2.2.1)
  let id = HttpMessageComponentId::try_from("@method").unwrap();
  let c = extract_derived_component(&req_or_res, &id).unwrap();
  assert_eq!(c.to_string(), "\"@method\": GET");

  // @target-uri (§2.2.2)
  let id = HttpMessageComponentId::try_from("@target-uri").unwrap();
  let c = extract_derived_component(&req_or_res, &id).unwrap();
  assert_eq!(c.to_string(), "\"@target-uri\": https://example.com/path?foo=bar&id=123&x=y");

  // @authority (§2.2.3)
  let id = HttpMessageComponentId::try_from("@authority").unwrap();
  let c = extract_derived_component(&req_or_res, &id).unwrap();
  assert_eq!(c.to_string(), "\"@authority\": example.com");

  // @scheme (§2.2.4)
  let id = HttpMessageComponentId::try_from("@scheme").unwrap();
  let c = extract_derived_component(&req_or_res, &id).unwrap();
  assert_eq!(c.to_string(), "\"@scheme\": https");

  // @path (§2.2.6)
  let id = HttpMessageComponentId::try_from("@path").unwrap();
  let c = extract_derived_component(&req_or_res, &id).unwrap();
  assert_eq!(c.to_string(), "\"@path\": /path");

  // @query (§2.2.7)
  let id = HttpMessageComponentId::try_from("@query").unwrap();
  let c = extract_derived_component(&req_or_res, &id).unwrap();
  assert_eq!(c.to_string(), "\"@query\": ?foo=bar&id=123&x=y");

  // @query-param;name="id" (§2.2.8)
  let id = HttpMessageComponentId::try_from("\"@query-param\";name=\"id\"").unwrap();
  let c = extract_derived_component(&req_or_res, &id).unwrap();
  assert_eq!(c.to_string(), "\"@query-param\";name=\"id\": 123");
}

// ---- RFC 9421 §2.4: @query-param;name="...";req on response ----

#[tokio::test]
async fn test_response_with_query_param_req_sign_verify() {
  // Build a request with query params
  let req = build_query_request();
  // Build a response
  let body = Full::new(bytes::Bytes::new()).map_err(|never| match never {}).boxed();
  let mut res: Response<BoxBody> = Response::builder().status(200).body(body).unwrap();

  // Response signature covering @status + @query-param;name="id";req
  let covered = ["@status", "\"@query-param\";name=\"id\";req"];
  let covered_components = covered
    .iter()
    .map(|v| HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();

  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();
  signature_params.set_key_info(&secret_key);

  res
    .set_message_signature(&signature_params, &secret_key, None, Some(&req))
    .await
    .unwrap();

  assert!(req.headers().get("signature-input").is_none(), "request should not be modified");
  assert!(res.headers().get("signature-input").is_some(), "signature-input header is missing on response");
  assert!(res.headers().get("signature").is_some(), "signature header is missing on response");

  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = res.verify_message_signature(&public_key, None, Some(&req)).await;
  assert!(verification_res.is_ok(), "signature verification failed: {:?}", verification_res.err());
}

// ---- RFC 9421: Response must reject request-derived components without `req` ----

#[tokio::test]
async fn test_response_rejects_derived_component_without_req() {
  let body = Full::new(bytes::Bytes::new()).map_err(|never| match never {}).boxed();
  let mut res: Response<BoxBody> = Response::builder().status(200).body(body).unwrap();

  // `@method` without `req` on a response — must fail
  let covered = vec![
    HttpMessageComponentId::try_from("@status").unwrap(),
    HttpMessageComponentId::try_from("@method").unwrap(),
  ];

  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered).unwrap();
  signature_params.set_key_info(&secret_key);

  let result = res
    .set_message_signature(&signature_params, &secret_key, None, None as Option<&Request<()>>)
    .await;
  assert!(result.is_err(), "expected Err when using `@method` without `req` on response");
}
