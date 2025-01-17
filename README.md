# httpsig-rs

> **Work in Progress**

[![httpsig](https://img.shields.io/crates/v/httpsig.svg)](https://crates.io/crates/httpsig)
[![httpsig](https://docs.rs/httpsig/badge.svg)](https://docs.rs/httpsig)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Unit Test](https://github.com/junkurihara/httpsig-rs/actions/workflows/ci.yml/badge.svg)

Implementation of [IETF RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421) of http message signatures.

This crates provides a basic library [httpsig](./httpsig) and [its extension](./httpsig-hyper/) of [`hyper`](https://github.com/hyperium/hyper)'s http library. At this point, our library can sign and verify request and response messages of only `hyper`.

## Supported Signature Algorithms

- [x] HMAC using SHA-256
- [x] Ed25519
- [x] ECDSA-P256 using SHA-256
- [ ] ECDSA-P384 using SHA-384

~~- [ ] RSASSA-PSS using SHA-512~~

~~- [ ] RSASSA-PKCS1-v1_5 using SHA-256~~

At this point, we have no plan to support RSA signature due to [the problem related to the non-constant time operation](https://github.com/RustCrypto/RSA/issues/19), i.e., [Mervin Attack](https://people.redhat.com/~hkario/marvin/).

## Usage of Extension for `hyper` (`httpsig-hyper`)

This is a case signing and verifying a signature generated with asymmetric cryptography (like EdDSA), where `PUBLIC_KEY_STRING` and `SECRET_KEY_STRING` is a public and private keys in PEM format, respectively. Generating and verifying a MAC through symmetric crypto (HMAC-SHA256) is also supported.

### Signing and Verifying a Request

```rust
use http::Request;
use http_body_util::Full;
use httpsig_hyper::{prelude::*, *};

type SignatureName = String;
const COVERED_COMPONENTS: &[&str] = &["@method", "date", "content-type", "content-digest"];

/// Signer function that generates a request with a signature
async fn signer<B>(&mut req: Request<B>) -> HttpSigResult<()> {
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
async fn verifier<B>(req: &Request<B>) -> HttpSigResult<SignatureName> {
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

  // if needed, content-digest can be verified separately
  let verified_request = request_from_sender.verify_content_digest().await;
  assert!(verified_request.is_ok());
}

```

### Signing and Verifying a Response

```rust
use http::{Request, Response};
use http_body_util::Full;
use httpsig_hyper::{prelude::*, *};

type SignatureName = String;

/// This includes the method of the request corresponding to the request (the second element)
const COVERED_COMPONENTS: &[&str] = &["@status", "\"@method\";req", "date", "content-type", "content-digest"];

/// Signer function that generates a response with a signature from response itself and corresponding request
async fn signer<B>(&mut res: Response<B>, corresponding_req: &Request<B>) -> HttpSigResult<()> {
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
    .set_message_signature(&signature_params, &secret_key, Some("custom_sig_name"), Some(corresponding_req))
    .await
}

/// Validation function that verifies a response with a signature from response itself and sent request
async fn verifier<B>(res: &Response<B>, sent_req: &Request<B>) -> HttpSigResult<SignatureName> {
  let public_key = PublicKey::from_pem(PUBLIC_KEY_STRING).unwrap();
  let key_id = public_key.key_id();

  // verify signature with checking key_id
  res.verify_message_signature(&public_key, Some(&key_id), Some(sent_req)).await
}
```

## Examples

See [./httpsig-hyper/examples](./httpsig-hyper/examples/) for detailed examples with `hyper` extension.
