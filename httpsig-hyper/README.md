# httpsig-hyper

[![httpsig-hyper](https://img.shields.io/crates/v/httpsig-hyper.svg)](https://crates.io/crates/httpsig-hyper)
[![httpsig-hyper](https://docs.rs/httpsig-hyper/badge.svg)](https://docs.rs/httpsig-hyper)

## Example

You can run a basic example in [./examples](./examples/) as follows.

```sh:
% cargo run --examples hyper
```

## Caveats

Note that even if `content-digest` header is specified as one of covered component for signature, the verification process of `httpsig-hyper` doesn't validate the message body. Namely, it only check the consistency between the signature and message components.
