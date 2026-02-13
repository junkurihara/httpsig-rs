use http::{Request, Response};
use http_body_util::Full;
use httpsig_hyper::{prelude::*, *};

type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, HyperDigestError>;
type SignatureName = String;

const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
const HMACSHA256_SECRET_KEY: &str =
  r##"uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="##;

const COVERED_COMPONENTS: &[&str] = &["@status", "\"@method\";req", "date", "content-type", "\"content-digest\";req"];

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

/// Sender function that generates a request with a signature
async fn sender_ed25519(res: &mut Response<BoxBody>, received_req: &Request<BoxBody>) {
  println!("Signing with ED25519 with key id");
  // build signature params that indicates objects to be signed
  let covered_components = COVERED_COMPONENTS
    .iter()
    .map(|v| message_component::HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

  // set signing/verifying key information, alg and keyid with ed25519
  let secret_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  signature_params.set_key_info(&secret_key);

  // set signature with custom signature name
  res
    .set_message_signature(&signature_params, &secret_key, Some("siged25519"), Some(received_req))
    .await
    .unwrap();
}

/// Sender function that generates a request with a signature
async fn sender_hs256(res: &mut Response<BoxBody>, received_req: &Request<BoxBody>) {
  println!("Signing with HS256 with key id and random nonce");
  // build signature params that indicates objects to be signed
  let covered_components = COVERED_COMPONENTS
    .iter()
    .map(|v| message_component::HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

  // set signing/verifying key information, alg and keyid and random noce with hmac-sha256
  let shared_key = SharedKey::from_base64(&AlgorithmName::HmacSha256, HMACSHA256_SECRET_KEY).unwrap();
  signature_params.set_key_info(&shared_key);
  signature_params.set_random_nonce();

  res
    .set_message_signature(&signature_params, &shared_key, Some("sighs256"), Some(received_req))
    .await
    .unwrap();
}

/// Receiver function that verifies a request with a signature of ed25519
async fn receiver_ed25519<B>(res: &Response<B>, sent_req: &Request<BoxBody>) -> HyperSigResult<SignatureName>
where
  B: http_body::Body + Send + Sync,
{
  println!("Verifying ED25519 signature");
  let public_key = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
  let key_id = public_key.key_id();

  // verify signature with checking key_id
  res.verify_message_signature(&public_key, Some(&key_id), Some(sent_req)).await
}

/// Receiver function that verifies a request with a signature of hmac-sha256
async fn receiver_hmac_sha256<B>(res: &Response<B>, sent_req: &Request<BoxBody>) -> HyperSigResult<SignatureName>
where
  B: http_body::Body + Send + Sync,
{
  println!("Verifying HMAC-SHA256 signature");
  let shared_key = SharedKey::from_base64(&AlgorithmName::HmacSha256, HMACSHA256_SECRET_KEY).unwrap();
  let key_id = VerifyingKey::key_id(&shared_key);

  // verify signature with checking key_id
  res.verify_message_signature(&shared_key, Some(&key_id), Some(sent_req)).await
}

async fn scenario_multiple_signatures() {
  println!("--------------  Scenario: Multiple signatures  --------------");

  let sent_req = build_request().await;
  println!("Header of request received:\n{:#?}", sent_req.headers());

  let mut response_from_sender = build_response().await;
  println!("Request header before signing:\n{:#?}", response_from_sender.headers());

  // sender signs a signature of ed25519 and hmac-sha256
  sender_ed25519(&mut response_from_sender, &sent_req).await;
  sender_hs256(&mut response_from_sender, &sent_req).await;

  println!(
    "Response header separately signed by ED25519 and HS256:\n{:#?}",
    response_from_sender.headers()
  );

  let signature_inputs = response_from_sender
    .headers()
    .get_all("signature-input")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let signatures = response_from_sender
    .headers()
    .get_all("signature")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  assert!(signature_inputs.iter().any(|v| v.starts_with(r##"siged25519=("##)));
  assert!(signature_inputs.iter().any(|v| v.starts_with(r##"sighs256=("##)));
  assert!(signatures.iter().any(|v| v.starts_with(r##"siged25519=:"##)));
  assert!(signatures.iter().any(|v| v.starts_with(r##"sighs256=:"##)));

  // receiver verifies the request with signatures
  // every signature is independent and verified separately
  let verification_res_ed25519 = receiver_ed25519(&response_from_sender, &sent_req).await;
  assert!(verification_res_ed25519.is_ok());
  println!("ED25519 signature is verified");
  let verification_res_hs256 = receiver_hmac_sha256(&response_from_sender, &sent_req).await;
  assert!(verification_res_hs256.is_ok());
  println!("HMAC-SHA256 signature is verified");

  // if needed, content-digest can be verified separately
  let verified_request = response_from_sender.verify_content_digest().await;
  assert!(verified_request.is_ok());
  println!("Content-Digest header is verified");
}

async fn scenario_single_signature_ed25519() {
  println!("--------------  Scenario: Single signature with Ed25519  --------------");

  let sent_req = build_request().await;
  println!("Header of request received:\n{:#?}", sent_req.headers());

  let mut response_from_sender = build_response().await;
  println!("Response header before signing:\n{:#?}", response_from_sender.headers());

  // sender signs a signature of ed25519
  sender_ed25519(&mut response_from_sender, &sent_req).await;

  println!("Response header signed by ED25519:\n{:#?}", response_from_sender.headers());

  let signature_inputs = response_from_sender
    .headers()
    .get_all("signature-input")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let signatures = response_from_sender
    .headers()
    .get_all("signature")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  assert!(signature_inputs.iter().any(|v| v.starts_with(r##"siged25519=("##)));
  assert!(signatures.iter().any(|v| v.starts_with(r##"siged25519=:"##)));

  // receiver verifies the request with signatures
  // every signature is independent and verified separately
  let verification_res_ed25519 = receiver_ed25519(&response_from_sender, &sent_req).await;
  assert!(verification_res_ed25519.is_ok());
  println!("ED25519 signature is verified");

  // if needed, content-digest can be verified separately
  let verified_request = response_from_sender.verify_content_digest().await;
  assert!(verified_request.is_ok());
  println!("Content-Digest header is verified");
}

#[tokio::main]
async fn main() {
  scenario_single_signature_ed25519().await;
  println!("-------------------------------------------------------------");
  scenario_multiple_signatures().await;
  println!("-------------------------------------------------------------");
}
