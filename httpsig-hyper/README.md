# httpsig-hyper

[![httpsig-hyper](https://img.shields.io/crates/v/httpsig-hyper.svg)](https://crates.io/crates/httpsig-hyper)
[![httpsig-hyper](https://docs.rs/httpsig-hyper/badge.svg)](https://docs.rs/httpsig-hyper)

## Examples

You can run a basic example in [./examples](./examples/) as follows.

### Sign and Verify a Request

```sh
% cargo run --example hyper-request
```

### Sign and Verify a Response

```sh
% cargo run --example hyper-response
```

## Caveats

Note that even if `content-digest` header is specified as one of covered component for signature, the verification process of `httpsig-hyper` doesn't validate the message body automatically. Namely, it only check the consistency between the signature and message components.

If you need to verify the body of a given message when `content-digest` is covered in `signature-input` header, you need to invoke `verify_content_digest()` function as follows.

```rust
// first verifies the signature according to `signature-input` header
let alg = AlgorithmName::Ed25519;
let public_key = PublicKey::from_pem(&alg, EDDSA_PUBLIC_KEY).unwrap();
let signature_verification = req.verify_message_signature(&public_key, None).await;
assert!(verification_res.is_ok());

// if needed, content-digest can be verified separately (only if content-digest header is included in the header)
let verified_request = request_from_sender.verify_content_digest().await;
assert!(verified_request.is_ok())
```

In the context of cryptography, the content-digest of *covered components* in signature-input is verified in the process of signature verification. So, hash value of `content-digest` is verified. To check if the `content-digest` is correctly bound with the message body, we need to run the hashing process separately.
