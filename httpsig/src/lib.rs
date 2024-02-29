mod crypto;
mod error;
mod message_component;
mod signature_base;
mod signature_params;
mod trace;
mod util;

pub mod prelude {
  pub mod message_component {
    pub use crate::message_component::{
      DerivedComponentName, HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName, HttpMessageComponentParam,
    };
  }

  pub use crate::{
    crypto::{AlgorithmName, PublicKey, SecretKey, SharedKey, SigningKey, VerifyingKey},
    error::{HttpSigError, HttpSigResult},
    signature_base::{HttpSignature, HttpSignatureBase, HttpSignatureHeaders, HttpSignatureHeadersMap},
    signature_params::HttpSignatureParams,
  };
}

/* ----------------------------------------------------------------- */
#[cfg(test)]
mod tests {
  use super::prelude::*;
  use base64::{engine::general_purpose, Engine as _};

  /* ----------------------------------------------------------------- */
  // params from https://datatracker.ietf.org/doc/html/rfc9421#name-signing-a-request-using-ed2
  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
"##;
  const EDDSA_SIGNATURE_BASE: &str = r##""date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""##;
  const EDDSA_SIGNATURE_VALUE: &str = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
  const _EDDSA_SIGNATURE_RESULT: &str = r##"Signature-Input: sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"
Signature: sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"##;

  #[test]
  fn test_using_test_vector_ed25519() {
    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    assert_eq!(pk.key_id(), sk.public_key().key_id());

    let data = EDDSA_SIGNATURE_BASE.as_bytes();
    let binary_signature = general_purpose::STANDARD.decode(EDDSA_SIGNATURE_VALUE).unwrap();
    let verification_result = pk.verify(data, &binary_signature);
    assert!(verification_result.is_ok());

    let signature = sk.sign(EDDSA_SIGNATURE_BASE.as_bytes()).unwrap();
    let signature_value = general_purpose::STANDARD.encode(signature);
    // println!("{}", signature_value);
    let signature_bytes = general_purpose::STANDARD.decode(signature_value).unwrap();
    let verification_result = pk.verify(EDDSA_SIGNATURE_BASE.as_bytes(), &signature_bytes);
    assert!(verification_result.is_ok());
  }

  /* ----------------------------------------------------------------- */
  // params from https://datatracker.ietf.org/doc/html/rfc9421#name-signing-a-request-using-hma
  const HMACSHA256_SECRET_KEY: &str =
    r##"uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="##;
  const HMACSHA256_SIGNATURE_BASE: &str = r##""date": Tue, 20 Apr 2021 02:07:55 GMT
"@authority": example.com
"content-type": application/json
"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret""##;
  const HMACSHA256_SIGNATURE_VALUE: &str = r##"pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="##;

  #[test]
  fn test_using_test_vector_hmac_sha256() {
    let sk = SharedKey::from_base64(HMACSHA256_SECRET_KEY).unwrap();

    let data = HMACSHA256_SIGNATURE_BASE.as_bytes();
    let binary_signature = general_purpose::STANDARD.decode(HMACSHA256_SIGNATURE_VALUE).unwrap();
    let verification_result = sk.verify(data, &binary_signature);
    assert!(verification_result.is_ok());

    let signature = sk.sign(HMACSHA256_SIGNATURE_BASE.as_bytes()).unwrap();
    let signature_value = general_purpose::STANDARD.encode(signature);
    assert_eq!(signature_value, HMACSHA256_SIGNATURE_VALUE.to_string());

    let signature_bytes = general_purpose::STANDARD.decode(signature_value).unwrap();
    let verification_result = sk.verify(HMACSHA256_SIGNATURE_BASE.as_bytes(), &signature_bytes);
    assert!(verification_result.is_ok());
  }

  /* ----------------------------------------------------------------- */
  const COMPONENT_LINES: &[&str] = &[
    r##""date": Tue, 20 Apr 2021 02:07:55 GMT"##,
    r##""@method": POST"##,
    r##""@path": /foo"##,
    r##""@authority": example.com"##,
    r##""content-type": application/json"##,
    r##""content-length": 18"##,
  ];
  const SIGNATURE_PARAMS: &str =
    r##"("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""##;

  #[test]
  fn test_with_directly_using_crypto_api() {
    let signature_params = HttpSignatureParams::try_from(SIGNATURE_PARAMS).unwrap();
    let component_lines = COMPONENT_LINES
      .iter()
      .map(|&line| message_component::HttpMessageComponent::try_from(line).unwrap())
      .collect::<Vec<_>>();

    let signature_base = HttpSignatureBase::try_new(&component_lines, &signature_params).unwrap();
    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();

    let signature_bytes = sk.sign(&signature_base.as_bytes()).unwrap();
    let verification_result = pk.verify(&signature_base.as_bytes(), &signature_bytes);
    assert!(verification_result.is_ok());
  }

  #[test]
  fn test_with_build_signature_api() {
    let component_lines = COMPONENT_LINES
      .iter()
      .map(|&line| message_component::HttpMessageComponent::try_from(line).unwrap())
      .collect::<Vec<_>>();

    // sender
    let signature_params = HttpSignatureParams::try_from(SIGNATURE_PARAMS).unwrap();
    let signature_base = HttpSignatureBase::try_new(&component_lines, &signature_params).unwrap();
    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let signature_headers = signature_base.build_signature_headers(&sk, Some("sig-b26")).unwrap();
    let signature_params_header_string = signature_headers.signature_input_header_value();
    let signature_header_string = signature_headers.signature_header_value();

    assert_eq!(signature_params_header_string, format!("sig-b26={}", SIGNATURE_PARAMS));
    assert!(signature_header_string.starts_with("sig-b26=:") && signature_header_string.ends_with(':'));

    // receiver
    let header_map = HttpSignatureHeaders::try_parse(&signature_header_string, &signature_params_header_string).unwrap();
    let received_signature_headers = header_map.get("sig-b26").unwrap();
    let received_signature_base =
      HttpSignatureBase::try_new(&component_lines, received_signature_headers.signature_params()).unwrap();
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let verification_result = received_signature_base.verify_signature_headers(&pk, received_signature_headers);
    assert!(verification_result.is_ok());
  }
}
