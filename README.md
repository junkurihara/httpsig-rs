# httpsig-rs

> **Work in Progress**

[![httpsig](https://img.shields.io/crates/v/httpsig.svg)](https://crates.io/crates/httpsig)
[![httpsig](https://docs.rs/httpsig/badge.svg)](https://docs.rs/httpsig)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Unit Test](https://github.com/junkurihara/rust-rpxy/actions/workflows/ci.yml/badge.svg)

Implementation of [IETF draft of http message signatures](https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/). Our implementation is currently based on [Draft-19](https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/19/).

This crates provides a basic library [httpsig](./httpsig) and [its extension](./httpsig-hyper/) of `hyper`'s http library. At this point, our library can sign and verify only request messages of hyper. (TODO: response message signature)

## Usage of Extension for `hyper` (`httpsig-hyper`)

```rust
use http::Request;
use http_body_util::Full;
use httpsig_hyper::{prelude::*, *};

const COVERED_COMPONENTS: &[&str] = &["@method", "date", "content-type", "content-digest"];

/// Signer function that generates a request with a signature
async fn signer<B>(&mut req: Request<B>) -> anyhow::Result<()> {
  // build signature params that indicates objects to be signed
  let covered_components = COVERED_COMPONENTS
    .iter()
    .map(|v| message_component::HttpMessageComponentId::try_from(*v))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

  // set signing/verifying key information, alg and keyid
  let secret_key = SecretKey::from_pem(SECRET_KEY_STRING).unwrap();
  signature_params.set_key_info(&secret_key);

  req
    .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"))
    .await
}

/// Validation function that verifies a request with a signature
async fn verifier<B>(req: &Request<B>) -> anyhow::Result<bool> {
  let public_key = PublicKey::from_pem(PUBLIC_KEY_STRING).unwrap();
  let key_id = public_key.key_id();

  // verify signature with checking key_id
  req.verify_message_signature(&public_key, Some(&key_id)).await
}

#[tokio::main]
async fn main() {
  let mut request_from_sender = ...;
  let res = signer(request_from_sender).await;
  assert!(res.is_ok())

  // receiver verifies the request with a signature
  let verified_message = receiver(&request_from_sender).await;
  assert!(verification_res.is_ok());
  assert!(verification_res.unwrap())

  // if needed, content-digest can be verified separately
  let verified_cd = request_from_sender.verify_content_digest().await.unwrap();
  assert!(verified);
}

```

## Examples

See [./httpsig-hyper/examples](./httpsig-hyper/examples/) for detailed examples with `hyper` extension.
