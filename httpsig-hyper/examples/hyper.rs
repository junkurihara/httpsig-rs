use http::Request;
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

/// Sender function that generates a request with a signature
async fn sender_ed25519(req: &mut Request<BoxBody>) {
  println!("Signing with ED25519 with key id");
  // build signature params that indicates objects to be signed
  let covered_components = COVERED_COMPONENTS
    .iter()
    .map(|v| message_component::HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

  // set signing/verifying key information, alg and keyid with ed25519
  let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
  signature_params.set_key_info(&secret_key);

  // set signature with custom signature name
  req
    .set_message_signature(&signature_params, &secret_key, Some("siged25519"))
    .await
    .unwrap();
}

/// Sender function that generates a request with a signature
async fn sender_hs256(req: &mut Request<BoxBody>) {
  println!("Signing with HS256 with key id and random nonce");
  // build signature params that indicates objects to be signed
  let covered_components = COVERED_COMPONENTS
    .iter()
    .map(|v| message_component::HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

  // set signing/verifying key information, alg and keyid and random noce with hmac-sha256
  let shared_key = SharedKey::from_base64(HMACSHA256_SECRET_KEY).unwrap();
  signature_params.set_key_info(&shared_key);
  signature_params.set_random_nonce();

  req
    .set_message_signature(&signature_params, &shared_key, Some("sighs256"))
    .await
    .unwrap();
}

/// Receiver function that verifies a request with a signature of ed25519
async fn receiver_ed25519<B>(req: &Request<B>) -> HyperSigResult<SignatureName>
where
  B: http_body::Body + Send + Sync,
{
  println!("Verifying ED25519 signature");
  let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
  let key_id = public_key.key_id();

  // verify signature with checking key_id
  req.verify_message_signature(&public_key, Some(&key_id)).await
}

/// Receiver function that verifies a request with a signature of hmac-sha256
async fn receiver_hmac_sha256<B>(req: &Request<B>) -> HyperSigResult<SignatureName>
where
  B: http_body::Body + Send + Sync,
{
  println!("Verifying HMAC-SHA256 signature");
  let shared_key = SharedKey::from_base64(HMACSHA256_SECRET_KEY).unwrap();
  let key_id = VerifyingKey::key_id(&shared_key);

  // verify signature with checking key_id
  req.verify_message_signature(&shared_key, Some(&key_id)).await
}

async fn scenario_multiple_signatures() {
  println!("--------------  Scenario: Multiple signatures  --------------");

  let mut request_from_sender = build_request().await;
  println!("Request header before signing:\n{:#?}", request_from_sender.headers());

  // sender signs a signature of ed25519 and hmac-sha256
  sender_ed25519(&mut request_from_sender).await;
  sender_hs256(&mut request_from_sender).await;

  println!(
    "Request header separately signed by ED25519 and HS256:\n{:#?}",
    request_from_sender.headers()
  );

  let signature_inputs = request_from_sender
    .headers()
    .get_all("signature-input")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let signatures = request_from_sender
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
  let verification_res_ed25519 = receiver_ed25519(&request_from_sender).await;
  assert!(verification_res_ed25519.is_ok());
  println!("ED25519 signature is verified");
  let verification_res_hs256 = receiver_hmac_sha256(&request_from_sender).await;
  assert!(verification_res_hs256.is_ok());
  println!("HMAC-SHA256 signature is verified");

  // if needed, content-digest can be verified separately
  let verified_request = request_from_sender.verify_content_digest().await;
  assert!(verified_request.is_ok());
  println!("Content-Digest header is verified");
}

async fn scenario_single_signature_ed25519() {
  println!("--------------  Scenario: Single signature with Ed25519  --------------");

  let mut request_from_sender = build_request().await;
  println!("Request header before signing:\n{:#?}", request_from_sender.headers());

  // sender signs a signature of ed25519
  sender_ed25519(&mut request_from_sender).await;

  println!("Request header signed by ED25519:\n{:#?}", request_from_sender.headers());

  let signature_inputs = request_from_sender
    .headers()
    .get_all("signature-input")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let signatures = request_from_sender
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
  let verification_res_ed25519 = receiver_ed25519(&request_from_sender).await;
  assert!(verification_res_ed25519.is_ok());
  println!("ED25519 signature is verified");

  // if needed, content-digest can be verified separately
  let verified_request = request_from_sender.verify_content_digest().await;
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
