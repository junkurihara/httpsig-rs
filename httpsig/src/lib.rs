mod crypto;
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
    crypto::{PublicKey, SecretKey, SharedKey, SigningKey, VerifyingKey},
    signature_base::{HttpSignatureBase, HttpSignatureHeaders},
    signature_params::HttpSignatureParams,
  };
}

#[cfg(test)]
mod tests {
  use super::prelude::*;
  use base64::{engine::general_purpose, Engine as _};
  // params from https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#name-signing-a-request-using-ed2
  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
"##;
  const SIGNATURE_BASE: &str = r##""date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""##;
  const SIGNATURE_VALUE: &str = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
  const _SIGNATURE_RESULT: &str = r##"Signature-Input: sig-b26=("date" "@method" "@path" "@authority" \
  "content-type" "content-length");created=1618884473\
  ;keyid="test-key-ed25519"
Signature: sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1\
  u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"##;

  #[test]
  fn test_using_test_vector() {
    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    assert_eq!(pk.key_id(), sk.public_key().key_id());

    let data = SIGNATURE_BASE.as_bytes();
    let binary_signature = general_purpose::STANDARD.decode(SIGNATURE_VALUE).unwrap();
    let verification_result = pk.verify(data, &binary_signature);
    assert!(verification_result.is_ok());

    let signature = sk.sign(SIGNATURE_BASE.as_bytes()).unwrap();
    let signature_value = general_purpose::STANDARD.encode(signature);
    // println!("{}", signature_value);
    let signature_bytes = general_purpose::STANDARD.decode(signature_value).unwrap();
    let verification_result = pk.verify(SIGNATURE_BASE.as_bytes(), &signature_bytes);
    assert!(verification_result.is_ok());
  }

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
  fn test_with_api() {
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
}
