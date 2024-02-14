use http::Request;
use http_body_util::Full;
use httpsig_hyper::{prelude::*, *};

type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, anyhow::Error>;

const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;

const COVERED_COMPONENTS: &[&str] = &["@method", "date", "content-type", "content-digest"];

async fn build_request() -> anyhow::Result<Request<BoxBody>> {
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

/// Sender function that generates a request with a signature
async fn sender() -> Request<BoxBody> {
  // build signature params that indicates objects to be signed
  let covered_components = COVERED_COMPONENTS
    .iter()
    .map(|v| message_component::HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

  // set signing/verifying key information, alg and keyid
  let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
  signature_params.set_key_info(&secret_key);

  // set signature with custom signature name
  let mut req = build_request().await.unwrap();
  req
    .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"))
    .await
    .unwrap();

  req
}

/// Receiver function that verifies a request with a signature
async fn receiver<B>(req: &Request<B>) -> Result<(), anyhow::Error>
where
  B: http_body::Body + Send + Sync,
{
  let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
  let key_id = public_key.key_id();

  // verify signature with checking key_id
  req.verify_message_signature(&public_key, Some(&key_id)).await
}

#[tokio::main]
async fn main() {
  // sender generates a request with a signature
  let request_from_sender = sender().await;

  let signature_input = request_from_sender
    .headers()
    .get("signature-input")
    .unwrap()
    .to_str()
    .unwrap();
  let signature = request_from_sender.headers().get("signature").unwrap().to_str().unwrap();
  assert!(signature_input.starts_with(r##"custom_sig_name=("##));
  assert!(signature.starts_with(r##"custom_sig_name=:"##));

  // receiver verifies the request with a signature
  let verification_res = receiver(&request_from_sender).await;
  assert!(verification_res.is_ok());

  // if needed, content-digest can be verified separately
  let verified_request = request_from_sender.verify_content_digest().await;
  assert!(verified_request.is_ok());
}
