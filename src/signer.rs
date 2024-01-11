// API design:
// let signature_params = SignatureParamsBuilder::default()
//   .created(1618884473)
//   .key_id("test-key-ed25519") // Should key_id be set at signer builder?
//   .headers(vec![...])
//   .build();
// let signer = HttpSignatureSignerBuilder::default()
//   .secret_key(SecretKey::HmacSha256(SymmetricKey::from(b"secret")))
//   .signature_params(signature_params)
//   .build();
