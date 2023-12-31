mod crypto;
use crypto::{PublicKey, SecretKey};
pub fn test() {
  println!("Hello, world!");
}

#[cfg(test)]
mod tests {
  use super::*;
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
  const SIGNATURE_VALUE: &str =
    "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
  const SIGNATURE_RESULT: &str = r##"Signature-Input: sig-b26=("date" "@method" "@path" "@authority" \
  "content-type" "content-length");created=1618884473\
  ;keyid="test-key-ed25519"
Signature: sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1\
  u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"##;

  #[test]
  fn test() {
    println!("{}", SIGNATURE_BASE);
    println!("{}", SIGNATURE_VALUE);
    println!("{}", SIGNATURE_RESULT);

    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    assert_eq!(pk.key_id(), sk.public_key().key_id());

    let data = SIGNATURE_BASE.as_bytes();
    let binary_signature = general_purpose::STANDARD.decode(SIGNATURE_VALUE).unwrap();
    let verification_result = pk.verify(data, &binary_signature);
    assert!(verification_result.is_ok());

    let signature = sk.sign(SIGNATURE_BASE.as_bytes()).unwrap();
    let signature_value = general_purpose::STANDARD.encode(signature);
    println!("{}", signature_value);
    let signature_bytes = general_purpose::STANDARD.decode(signature_value).unwrap();
    let verification_result = pk.verify(SIGNATURE_BASE.as_bytes(), &signature_bytes);
    assert!(verification_result.is_ok());
  }
}