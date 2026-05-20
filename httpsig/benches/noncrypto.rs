//! Benches of non crypto logic like signature base extraction or serialization.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use httpsig::prelude::{
  message_component::HttpMessageComponent, AlgorithmName, HttpSignatureBase, HttpSignatureHeaders,
  HttpSignatureParams, SecretKey,
};

const COMPONENT_LINES: &[&str] = &[
  r##""date": Tue, 20 Apr 2021 02:07:55 GMT"##,
  r##""@method": POST"##,
  r##""@path": /foo"##,
  r##""@authority": example.com"##,
  r##""content-type": application/json"##,
  r##""content-length": 18"##,
];
const SIGNATURE_PARAMS: &str = r##"("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""##;

fn construct_signature_base(signature_params: &str, component_lines: &[&str]) -> HttpSignatureBase {
  let signature_params = HttpSignatureParams::try_from(signature_params).unwrap();
  let component_lines = component_lines
    .iter()
    .map(|&line| HttpMessageComponent::try_from(line).unwrap())
    .collect::<Vec<_>>();
  HttpSignatureBase::try_new(component_lines, &signature_params).unwrap()
}

fn parse_signature_base(
  signature_input_header: &str,
  signature_header: &str,
  component_lines: &[&str],
) -> HttpSignatureBase {
  let header_map =
    HttpSignatureHeaders::try_parse(signature_header, signature_input_header).unwrap();
  let received_signature_headers = header_map.get("sig-b26").unwrap();
  let component_lines = component_lines
    .iter()
    .map(|&line| HttpMessageComponent::try_from(line).unwrap())
    .collect::<Vec<_>>();
  HttpSignatureBase::try_new(
    component_lines,
    received_signature_headers.signature_params(),
  )
  .unwrap()
}

/* ----------------------------------------------------------------- */
// params from https://datatracker.ietf.org/doc/html/rfc9421#name-signing-a-request-using-ed2
const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----
"##;

fn setup_signature_input() -> (String, String, &'static [&'static str]) {
  let component_lines = COMPONENT_LINES
    .iter()
    .map(|&line| HttpMessageComponent::try_from(line).unwrap())
    .collect::<Vec<_>>();

  // sender
  let signature_params = HttpSignatureParams::try_from(SIGNATURE_PARAMS).unwrap();
  let signature_base =
    HttpSignatureBase::try_new(component_lines.clone(), &signature_params).unwrap();
  let sk = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
  let signature_headers = signature_base
    .build_signature_headers(&sk, Some("sig-b26"))
    .unwrap();
  (
    signature_headers.signature_input_header_value(),
    signature_headers.signature_header_value(),
    COMPONENT_LINES,
  )
}

fn construct_parse(c: &mut Criterion) {
  c.bench_function("sig base try_new", |b| {
    b.iter(|| construct_signature_base(black_box(SIGNATURE_PARAMS), black_box(COMPONENT_LINES)))
  });
  c.bench_function("sig base try_parse", |b| {
    b.iter_batched_ref(
      || setup_signature_input(),
      |(signature_input_header, signature_header, component_lines)| {
        parse_signature_base(signature_input_header, signature_header, component_lines)
      },
      criterion::BatchSize::SmallInput,
    )
  });
}

criterion_group!(benches, construct_parse);
criterion_main!(benches);
