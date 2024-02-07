# httpsig-rs

> **Work in Progress**

[![httpsig](https://img.shields.io/crates/v/httpsig.svg)](https://crates.io/crates/httpsig)
[![httpsig](https://docs.rs/httpsig/badge.svg)](https://docs.rs/httpsig)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Unit Test](https://github.com/junkurihara/rust-rpxy/actions/workflows/ci.yml/badge.svg)

Implementation of [IETF draft of http message signatures](https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/). Our implementation is currently based on [Draft-19](https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/19/).

This crates provides a basic library [httpsig](../lib) and [its extension](./ext-hyper/) of `hyper`'s http library. At this point, our library can sign and verify only request messages of hyper. (TODO: response message signature)

## Usage of Extension for hyper (httpsig-hyper)

```rust:
use httpsig_hyper::{prelude::{message_component::*, *}, *};


const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;

const COVERED_COMPONENTS: &[&str] = &["@method", "date", "content-type", "content-digest"];

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

async fn set_and_verify() {
  // build signature params that indicates objects to be signed
  let covered_components = COVERED_COMPONENTS
      .iter()
      .map(|v| HttpMessageComponentId::try_from(*v))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

  // set signing/verifying key information, alg and keyid
  signature_params.set_key_info(&secret_key);

  // set signature with custom signature name
  req
    .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"))
    .await
    .unwrap();
  let signature_input = req.headers().get("signature-input").unwrap().to_str().unwrap();
  let signature = req.headers().get("signature").unwrap().to_str().unwrap();
  assert!(signature_input.starts_with(r##"custom_sig_name=("##));
  assert!(signature.starts_with(r##"custom_sig_name=:"##));

  // verify without checking key_id
  let public_key = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
  let verification_res = req.verify_message_signature(&public_key, None).await.unwrap();
  assert!(verification_res);

  // verify with checking key_id
  let key_id = public_key.key_id();
  let verification_res = req.verify_message_signature(&public_key, Some(&key_id)).await.unwrap();
  assert!(verification_res);

  // Fails if no matched key_id is found
  let verification_res = req.verify_message_signature(&public_key, Some("NotFoundKeyId")).await;
  assert!(verification_res.is_err());
}

```
