use super::AlgorithmName;
use crate::{
  error::{HttpSigError, HttpSigResult},
  trace::*,
};
use ecdsa::{
  elliptic_curve::{sec1::ToEncodedPoint, PublicKey as EcPublicKey, SecretKey as EcSecretKey},
  signature::{DigestSigner, DigestVerifier},
};
use ed25519_compact::{PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use p256::NistP256;
use p384::NistP384;
use pkcs8::{der::Decode, Document, PrivateKeyInfo};
use sha2::{Digest, Sha256, Sha384};
use spki::SubjectPublicKeyInfoRef;

#[cfg(feature = "rsa-signature")]
use rsa::{
  pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey},
  pkcs1v15, pss,
  signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier},
  RsaPrivateKey, RsaPublicKey,
};

#[allow(non_upper_case_globals, dead_code)]
/// Algorithm OIDs
mod algorithm_oids {
  /// OID for `id-ecPublicKey`, if you're curious
  pub const EC: &str = "1.2.840.10045.2.1";
  /// OID for `id-Ed25519`, if you're curious
  pub const Ed25519: &str = "1.3.101.112";
  #[cfg(feature = "rsa-signature")]
  /// OID for `id-rsaEncryption`, if you're curious
  pub const rsaEncryption: &str = "1.2.840.113549.1.1.1";
}
#[allow(non_upper_case_globals, dead_code)]
/// Params OIDs
mod params_oids {
  // OID for the NIST P-256 elliptic curve.
  pub const Secp256r1: &str = "1.2.840.10045.3.1.7";
  // OID for the NIST P-384 elliptic curve.
  pub const Secp384r1: &str = "1.3.132.0.34";
}

/* -------------------------------- */
#[derive(Debug, Clone)]
/// Secret key for http signature
/// Name conventions follow [Section-6.2.2, RFC9421](https://datatracker.ietf.org/doc/html/rfc9421#section-6.2.2)
pub enum SecretKey {
  /// ecdsa-p384-sha384
  EcdsaP384Sha384(EcSecretKey<NistP384>),
  /// ecdsa-p256-sha256
  EcdsaP256Sha256(EcSecretKey<NistP256>),
  /// ed25519
  Ed25519(Ed25519SecretKey),
  #[cfg(feature = "rsa-signature")]
  /// rsa-v1_5-sha256
  RsaV1_5Sha256(pkcs1v15::SigningKey<rsa::sha2::Sha256>),
  #[cfg(feature = "rsa-signature")]
  RsaPssSha512(pss::SigningKey<rsa::sha2::Sha512>),
}

impl SecretKey {
  /// from plain bytes
  pub fn from_bytes(alg: &AlgorithmName, bytes: &[u8]) -> HttpSigResult<Self> {
    match alg {
      AlgorithmName::EcdsaP256Sha256 => {
        debug!("Read P256 private key");
        let sk = EcSecretKey::from_bytes(bytes.into()).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
        Ok(Self::EcdsaP256Sha256(sk))
      }
      AlgorithmName::EcdsaP384Sha384 => {
        debug!("Read P384 private key");
        let sk = EcSecretKey::from_bytes(bytes.into()).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
        Ok(Self::EcdsaP384Sha384(sk))
      }
      AlgorithmName::Ed25519 => {
        debug!("Read Ed25519 private key");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        let sk = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed)).sk;
        Ok(Self::Ed25519(sk))
      }
      #[cfg(feature = "rsa-signature")]
      AlgorithmName::RsaV1_5Sha256 => {
        debug!("Read RSA private key");
        // read PrivateKeyInfo.private_key as RsaPrivateKey (RFC 3447), which is DER encoded RSAPrivateKey in PKCS#1
        let sk = RsaPrivateKey::from_pkcs1_der(bytes).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
        Ok(Self::RsaV1_5Sha256(pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(sk)))
      }
      #[cfg(feature = "rsa-signature")]
      AlgorithmName::RsaPssSha512 => {
        debug!("Read RSA-PSS private key");
        // read PrivateKeyInfo.private_key as RsaPrivateKey (RFC 3447), which is DER encoded RSAPrivateKey in PKCS#1
        let sk = RsaPrivateKey::from_pkcs1_der(bytes).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
        Ok(Self::RsaPssSha512(pss::SigningKey::<rsa::sha2::Sha512>::new(sk)))
      }
      _ => Err(HttpSigError::ParsePrivateKeyError("Unsupported algorithm".to_string())),
    }
  }
  /// parse der
  /// Derive secret key from der bytes
  pub fn from_der(alg: &AlgorithmName, der: &[u8]) -> HttpSigResult<Self> {
    let pki = PrivateKeyInfo::from_der(der).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;

    let sk_bytes = match pki.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        let param = pki
          .algorithm
          .parameters_oid()
          .map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
        let algorithm_name = match param.to_string().as_ref() {
          params_oids::Secp256r1 => AlgorithmName::EcdsaP256Sha256,
          params_oids::Secp384r1 => AlgorithmName::EcdsaP384Sha384,
          _ => return Err(HttpSigError::ParsePrivateKeyError("Unsupported curve".to_string())),
        };
        // assert algorithm
        if algorithm_name != *alg {
          return Err(HttpSigError::ParsePrivateKeyError("Algorithm mismatch".to_string()));
        }
        let sk_bytes = sec1::EcPrivateKey::try_from(pki.private_key)
          .map_err(|e| HttpSigError::ParsePrivateKeyError(format!("Error decoding EcPrivateKey: {e}")))?
          .private_key;
        sk_bytes
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        // assert algorithm
        if AlgorithmName::Ed25519 != *alg {
          return Err(HttpSigError::ParsePrivateKeyError("Algorithm mismatch".to_string()));
        }
        &pki.private_key[2..]
      }
      // rsa
      #[cfg(feature = "rsa-signature")]
      algorithm_oids::rsaEncryption => {
        // assert algorithm
        match alg {
          AlgorithmName::RsaV1_5Sha256 | AlgorithmName::RsaPssSha512 => {}
          _ => return Err(HttpSigError::ParsePrivateKeyError("Algorithm mismatch".to_string())),
        }
        pki.private_key
      }
      _ => return Err(HttpSigError::ParsePrivateKeyError("Unsupported algorithm".to_string())),
    };
    let sk = Self::from_bytes(alg, sk_bytes)?;
    Ok(sk)
  }

  /// Derive secret key from pem string
  pub fn from_pem(alg: &AlgorithmName, pem: &str) -> HttpSigResult<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
    if tag != "PRIVATE KEY" {
      return Err(HttpSigError::ParsePrivateKeyError("Invalid tag".to_string()));
    };
    Self::from_der(alg, doc.as_bytes())
  }

  /// Get public key from secret key
  pub fn public_key(&self) -> PublicKey {
    match &self {
      Self::EcdsaP256Sha256(key) => PublicKey::EcdsaP256Sha256(key.public_key()),
      Self::EcdsaP384Sha384(key) => PublicKey::EcdsaP384Sha384(key.public_key()),
      Self::Ed25519(key) => PublicKey::Ed25519(key.public_key()),
      #[cfg(feature = "rsa-signature")]
      Self::RsaV1_5Sha256(key) => PublicKey::RsaV1_5Sha256(key.verifying_key()),
      #[cfg(feature = "rsa-signature")]
      Self::RsaPssSha512(key) => PublicKey::RsaPssSha512(key.verifying_key()),
    }
  }
}

impl super::SigningKey for SecretKey {
  /// Sign data
  fn sign(&self, data: &[u8]) -> HttpSigResult<Vec<u8>> {
    match &self {
      Self::EcdsaP256Sha256(sk) => {
        debug!("Sign EcdsaP256Sha256");
        let sk = ecdsa::SigningKey::from(sk);
        let mut digest = <Sha256 as Digest>::new();
        digest.update(data);
        let sig: ecdsa::Signature<NistP256> = sk.sign_digest(digest);
        Ok(sig.to_bytes().to_vec())
      }
      Self::EcdsaP384Sha384(sk) => {
        debug!("Sign EcdsaP384Sha384");
        let sk = ecdsa::SigningKey::from(sk);
        let mut digest = <Sha384 as Digest>::new();
        digest.update(data);
        let sig: ecdsa::Signature<NistP384> = sk.sign_digest(digest);
        Ok(sig.to_bytes().to_vec())
      }
      Self::Ed25519(sk) => {
        debug!("Sign Ed25519");
        let sig = sk.sign(data, Some(ed25519_compact::Noise::default()));
        Ok(sig.as_ref().to_vec())
      }
      #[cfg(feature = "rsa-signature")]
      Self::RsaV1_5Sha256(sk) => {
        debug!("Sign RsaV1_5Sha256");
        let sig = sk.sign_with_rng(&mut rand::rng(), data);
        Ok(sig.to_vec())
      }
      #[cfg(feature = "rsa-signature")]
      Self::RsaPssSha512(sk) => {
        debug!("Sign RsaPssSha512");
        let sig = sk.sign_with_rng(&mut rand::rng(), data);
        Ok(sig.to_vec())
      }
    }
  }

  fn key_id(&self) -> String {
    use super::VerifyingKey;
    self.public_key().key_id()
  }

  fn alg(&self) -> AlgorithmName {
    use super::VerifyingKey;
    self.public_key().alg()
  }
}

impl super::VerifyingKey for SecretKey {
  fn verify(&self, data: &[u8], signature: &[u8]) -> HttpSigResult<()> {
    self.public_key().verify(data, signature)
  }

  fn key_id(&self) -> String {
    self.public_key().key_id()
  }

  fn alg(&self) -> AlgorithmName {
    self.public_key().alg()
  }
}

/* -------------------------------- */
#[derive(Debug, Clone)]
/// Public key for http signature, only for asymmetric algorithm
/// Name conventions follow [Section 6.2.2, RFC9421](https://datatracker.ietf.org/doc/html/rfc9421#section-6.2.2)
pub enum PublicKey {
  /// ecdsa-p256-sha256
  EcdsaP256Sha256(EcPublicKey<NistP256>),
  /// ecdsa-p384-sha384
  EcdsaP384Sha384(EcPublicKey<NistP384>),
  /// ed25519
  Ed25519(Ed25519PublicKey),
  #[cfg(feature = "rsa-signature")]
  /// rsa-v1_5-sha256
  RsaV1_5Sha256(pkcs1v15::VerifyingKey<rsa::sha2::Sha256>),
  #[cfg(feature = "rsa-signature")]
  /// rsa-pss-sha512
  RsaPssSha512(pss::VerifyingKey<rsa::sha2::Sha512>),
}

impl PublicKey {
  /// from plain bytes
  pub fn from_bytes(alg: &AlgorithmName, bytes: &[u8]) -> HttpSigResult<Self> {
    match alg {
      AlgorithmName::EcdsaP256Sha256 => {
        debug!("Read P256 public key");
        let pk = EcPublicKey::from_sec1_bytes(bytes).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        Ok(Self::EcdsaP256Sha256(pk))
      }
      AlgorithmName::EcdsaP384Sha384 => {
        debug!("Read P384 public key");
        let pk = EcPublicKey::from_sec1_bytes(bytes).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        Ok(Self::EcdsaP384Sha384(pk))
      }
      AlgorithmName::Ed25519 => {
        debug!("Read Ed25519 public key");
        let pk = ed25519_compact::PublicKey::from_slice(bytes).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        Ok(Self::Ed25519(pk))
      }
      #[cfg(feature = "rsa-signature")]
      AlgorithmName::RsaV1_5Sha256 => {
        debug!("Read RSA public key");
        // read RsaPublicKey in PKCS#1 DER format
        let pk = RsaPublicKey::from_pkcs1_der(bytes).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        Ok(Self::RsaV1_5Sha256(pkcs1v15::VerifyingKey::new(pk)))
      }
      #[cfg(feature = "rsa-signature")]
      AlgorithmName::RsaPssSha512 => {
        debug!("Read RSA-PSS public key");
        // read RsaPublicKey in PKCS#1 DER format
        let pk = RsaPublicKey::from_pkcs1_der(bytes).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        Ok(Self::RsaPssSha512(pss::VerifyingKey::new(pk)))
      }
      _ => Err(HttpSigError::ParsePublicKeyError("Unsupported algorithm".to_string())),
    }
  }

  #[allow(dead_code)]
  /// Convert from pem string
  pub fn from_pem(alg: &AlgorithmName, pem: &str) -> HttpSigResult<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
    if tag != "PUBLIC KEY" {
      return Err(HttpSigError::ParsePublicKeyError("Invalid tag".to_string()));
    };

    let spki_ref = SubjectPublicKeyInfoRef::from_der(doc.as_bytes())
      .map_err(|e| HttpSigError::ParsePublicKeyError(format!("Error decoding SubjectPublicKeyInfo: {e}").to_string()))?;

    let pk_bytes = match spki_ref.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        let param = spki_ref
          .algorithm
          .parameters_oid()
          .map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        let algorithm_name = match param.to_string().as_ref() {
          params_oids::Secp256r1 => AlgorithmName::EcdsaP256Sha256,
          params_oids::Secp384r1 => AlgorithmName::EcdsaP384Sha384,
          _ => return Err(HttpSigError::ParsePublicKeyError("Unsupported curve".to_string())),
        };
        // assert algorithm
        if algorithm_name != *alg {
          return Err(HttpSigError::ParsePublicKeyError("Algorithm mismatch".to_string()));
        }
        spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(HttpSigError::ParsePublicKeyError("Invalid public key".to_string()))?
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        // assert algorithm
        if AlgorithmName::Ed25519 != *alg {
          return Err(HttpSigError::ParsePublicKeyError("Algorithm mismatch".to_string()));
        }
        spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(HttpSigError::ParsePublicKeyError("Invalid public key".to_string()))?
      }
      // rsa
      #[cfg(feature = "rsa-signature")]
      algorithm_oids::rsaEncryption => {
        match alg {
          AlgorithmName::RsaV1_5Sha256 | AlgorithmName::RsaPssSha512 => {}
          _ => return Err(HttpSigError::ParsePublicKeyError("Algorithm mismatch".to_string())),
        }
        spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(HttpSigError::ParsePublicKeyError("Invalid public key".to_string()))?
      }
      _ => return Err(HttpSigError::ParsePublicKeyError("Unsupported algorithm".to_string())),
    };
    Self::from_bytes(alg, pk_bytes)
  }
}

impl super::VerifyingKey for PublicKey {
  /// Verify signature
  fn verify(&self, data: &[u8], signature: &[u8]) -> HttpSigResult<()> {
    match self {
      Self::EcdsaP256Sha256(pk) => {
        debug!("Verify EcdsaP256Sha256");
        let signature = ecdsa::Signature::<NistP256>::from_bytes(signature.into())
          .map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        let vk = ecdsa::VerifyingKey::from(pk);
        let mut digest = <Sha256 as Digest>::new();
        digest.update(data);
        vk.verify_digest(digest, &signature)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
      Self::EcdsaP384Sha384(pk) => {
        debug!("Verify EcdsaP384Sha384");
        let signature = ecdsa::Signature::<NistP384>::from_bytes(signature.into())
          .map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        let vk = ecdsa::VerifyingKey::from(pk);
        let mut digest = <Sha384 as Digest>::new();
        digest.update(data);
        vk.verify_digest(digest, &signature)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
      Self::Ed25519(pk) => {
        debug!("Verify Ed25519");
        let sig =
          ed25519_compact::Signature::from_slice(signature).map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        pk.verify(data, &sig)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
      #[cfg(feature = "rsa-signature")]
      Self::RsaV1_5Sha256(pk) => {
        debug!("Verify RsaV1_5Sha256");
        let sig = pkcs1v15::Signature::try_from(signature).map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        pk.verify(data, &sig)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
      #[cfg(feature = "rsa-signature")]
      Self::RsaPssSha512(pk) => {
        debug!("Verify RsaPssSha512");
        let sig = pss::Signature::try_from(signature).map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        pk.verify(data, &sig)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
    }
  }

  /// Create key id, created by SHA-256 hash of the public key bytes, then encoded in base64
  /// - For ECDSA keys, use the uncompressed SEC1 encoding of the public key point as the byte representation.
  /// - For Ed25519 keys, use the raw 32-byte public key.
  /// - For RSA keys, use the DER encoding of the RSAPublicKey structure in PKCS#1 format.
  fn key_id(&self) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let bytes = match self {
      Self::EcdsaP256Sha256(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
      Self::EcdsaP384Sha384(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
      Self::Ed25519(vk) => vk.as_ref().to_vec(),
      #[cfg(feature = "rsa-signature")]
      Self::RsaV1_5Sha256(vk) => vk
        .as_ref()
        .to_pkcs1_der()
        .map(|der| der.as_bytes().to_vec())
        .unwrap_or(b"rsa-der-serialization-failed".to_vec()),
      #[cfg(feature = "rsa-signature")]
      Self::RsaPssSha512(vk) => vk
        .as_ref()
        .to_pkcs1_der()
        .map(|der| der.as_bytes().to_vec())
        .unwrap_or(b"rsa-der-serialization-failed".to_vec()),
    };
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    general_purpose::STANDARD.encode(hash)
  }

  /// Get the algorithm name
  fn alg(&self) -> AlgorithmName {
    match self {
      Self::EcdsaP256Sha256(_) => AlgorithmName::EcdsaP256Sha256,
      Self::EcdsaP384Sha384(_) => AlgorithmName::EcdsaP384Sha384,
      Self::Ed25519(_) => AlgorithmName::Ed25519,
      #[cfg(feature = "rsa-signature")]
      Self::RsaV1_5Sha256(_) => AlgorithmName::RsaV1_5Sha256,
      #[cfg(feature = "rsa-signature")]
      Self::RsaPssSha512(_) => AlgorithmName::RsaPssSha512,
    }
  }
}

#[cfg(test)]
mod tests {
  use p256::elliptic_curve::group::GroupEncoding;

  use super::*;
  use std::matches;

  const P256_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv7zxW56ojrWwmSo1
4uOdbVhUfj9Jd+5aZIB9u8gtWnihRANCAARGYsMe0CT6pIypwRvoJlLNs4+cTh2K
L7fUNb5i6WbKxkpAoO+6T3pMBG5Yw7+8NuGTvvtrZAXduA2giPxQ8zCf
-----END PRIVATE KEY-----
"##;
  const P256_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERmLDHtAk+qSMqcEb6CZSzbOPnE4d
ii+31DW+YulmysZKQKDvuk96TARuWMO/vDbhk777a2QF3bgNoIj8UPMwnw==
-----END PUBLIC KEY-----
"##;
  const P384_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCPYbeLLlIQKUzVyVGH
MeuFp/9o2Lr+4GrI3bsbHuViMMceiuM+8xqzFCSm4Ltl5UyhZANiAARKg3yM+Ltx
n4ZptF3hI6Q167crEtPRklCEsRTyWUqy+VrrnM5LU/+fqxVbyniBZHd4vmQVYtjF
xsv8P3DpjvpKJZqFfVdIr2ZR+kYDKHwIruIF9fCPawAH2tnbuc3xEzQ=
-----END PRIVATE KEY-----
"##;
  const P384_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAESoN8jPi7cZ+GabRd4SOkNeu3KxLT0ZJQ
hLEU8llKsvla65zOS1P/n6sVW8p4gWR3eL5kFWLYxcbL/D9w6Y76SiWahX1XSK9m
UfpGAyh8CK7iBfXwj2sAB9rZ27nN8RM0
-----END PUBLIC KEY-----
"##;

  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;

  #[cfg(feature = "rsa-signature")]
  const RSA2048_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCrjtdIxemmmL9V
wfp7qqwytfRDZqQM6XNWcAi3x+j5dHFFIKKWQktJ7eCTRYQrBwjQs5sb0ieNUYwQ
vTIH53z9PqKl1bCIk/6Pago2JNBQAUP9DSs+zcYYC1TYwPM12mxIqz6tHVBabBuG
49OoqWGgU4J5YkXvjyNFPVK1+dePLalm4/jUJb4VpbppN5NQ9qaqRTB3vQPW9i3D
uy2hefxh7FGfKx9BwrtKcV4JmjN9IjPpdjZTex/8GF3eIiePkHIJS88w8lkC4F03
06EuaMRs6KyWpj1aof+LvMG6iIRAigc0K//4tTwfKALRky4tW9JAYe3cFACDulu2
VXKGatq1AgMBAAECggEAH/cOb9XIci0VwXHSLQag7RXv/Dr8qBc7UUiwpyWNaCVl
EX9CLAMQKiczZ91VAftejhxY8zcV/YPLODc4QjbEmB76iTGmodwJW0lju7DiS3Xg
6B5zB1Gp7kL2PSi+aDNZZ7TYicLjfOWVv21lu5BLy2aj8d/4rekapkUFyzhRDLEk
E9/mvztCrLjLXMS6SFXY/rjfwckBT/tACbmgHInzRcoyX75FYyGtOc3w1S1tXEM8
7j/7EHZf+mNcHlpV5OMw+StVfl1Qwx8eJ9ZW1TmZEoysRe4zj/ej7+wTBSAC7AoA
UVB6G8hVU1NP+KD7Z9/6SvfJGvj8yR1HdBE5BZ54JQKBgQDfkpDEH4EH0pRSd867
nrijAwnqd4xdP11aOwgrrppxavUWAmd3vmki8k4O3ghkz8MtNd+bTcZNKcl4ioS3
boFA++wZQuzPBu6dbwlM9QX0VyzKAmGITrcnFrxCk3k8d6r9DzTVrzY8oK7nvo+1
n9QYtlBs/SyJZl4McEOCV0fsowKBgQDEcO6KkwQPt//Qm6Qb1ImrQQ1kgvOu77iG
R5Gn/FkURJvy+I4g9ANRXmHFTcdMSIS3dzY5Zr4kwa0UYJ/ivQ5QYwzYISiW3kgj
jmoLhxfWOXaO+vGNBXoZb5JkKrT2pnLlbbeiHaur6jfg20T2w2whts4vJ8aI6V3k
HagrXuz4xwKBgQDWhMhZFq109w4QTxrTFYmuCAVkr07ETj9hi5DccQ2J1AnUE3x5
/f7dZEeXpl3BdUSeRboHR0oF0hmZirerVeG5m7+/wWJ9hvY/o0H2UIhlGZxFPKGe
64B7hiofa2eBqIUtiYC1pAfTho4smMFFkVUuXQiwewBX2hxVrQZpsxu1JwKBgEwH
fXuqvPase1ks9A5Fa2cZzWoqeNArPdrS1mAS/hMnHsiiRLgiWSpkAilQGiO/KYas
oBMFXfBx+WAaqacjDugz/eOkqcYCkB8a3pZJmgMyyF08aMLw7LntgdY85T9VWsDL
fzhCjZADHc9sbjunlTFTRGfh2ChjUhCZHd5zZfo/AoGBANk7kXrHZlAsmEEoeA8R
yVpIaTIu64SzCsn4lWzh02zuSB20uNzYdNYBkHT/JHMvV4ctxjAXjDWI8aYzHaHY
KDYy4jUp2TeTPBpqwS24KzFaFx0y2U99TWrzt6sQJr7Y9NlR7S0znc/L7wwFobjr
XVdlU40OaPP7xs0er/tWVAPY
-----END PRIVATE KEY-----"##;

  #[cfg(feature = "rsa-signature")]
  const RSA2048_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq47XSMXpppi/VcH6e6qs
MrX0Q2akDOlzVnAIt8fo+XRxRSCilkJLSe3gk0WEKwcI0LObG9InjVGMEL0yB+d8
/T6ipdWwiJP+j2oKNiTQUAFD/Q0rPs3GGAtU2MDzNdpsSKs+rR1QWmwbhuPTqKlh
oFOCeWJF748jRT1StfnXjy2pZuP41CW+FaW6aTeTUPamqkUwd70D1vYtw7stoXn8
YexRnysfQcK7SnFeCZozfSIz6XY2U3sf/Bhd3iInj5ByCUvPMPJZAuBdN9OhLmjE
bOislqY9WqH/i7zBuoiEQIoHNCv/+LU8HygC0ZMuLVvSQGHt3BQAg7pbtlVyhmra
tQIDAQAB
-----END PUBLIC KEY-----"##;

  #[test]
  fn test_from_bytes() {
    let ed25519_kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::default());
    let ed25519_sk = ed25519_kp.sk.seed().to_vec();
    let ed25519_pk = ed25519_kp.pk.as_ref();
    let sk = SecretKey::from_bytes(&AlgorithmName::Ed25519, &ed25519_sk).unwrap();
    assert!(matches!(sk, SecretKey::Ed25519(_)));
    let pk = PublicKey::from_bytes(&AlgorithmName::Ed25519, ed25519_pk).unwrap();
    assert!(matches!(pk, PublicKey::Ed25519(_)));

    let mut rng = rand_085::thread_rng();
    let es256_sk = p256::ecdsa::SigningKey::random(&mut rng);
    let es256_pk = es256_sk.verifying_key();
    let sk = SecretKey::from_bytes(&AlgorithmName::EcdsaP256Sha256, es256_sk.to_bytes().as_ref()).unwrap();
    assert!(matches!(sk, SecretKey::EcdsaP256Sha256(_)));
    let pk_bytes = es256_pk.as_affine().to_bytes();
    let pk = PublicKey::from_bytes(&AlgorithmName::EcdsaP256Sha256, pk_bytes.as_ref()).unwrap();
    assert!(matches!(pk, PublicKey::EcdsaP256Sha256(_)));
  }

  #[test]
  fn test_from_pem() {
    let sk = SecretKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_SECRET_KEY).unwrap();
    assert!(matches!(sk, SecretKey::EcdsaP256Sha256(_)));
    let pk = PublicKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::EcdsaP256Sha256(_)));

    let sk = SecretKey::from_pem(&AlgorithmName::EcdsaP384Sha384, P384_SECRET_KEY).unwrap();
    assert!(matches!(sk, SecretKey::EcdsaP384Sha384(_)));
    let pk = PublicKey::from_pem(&AlgorithmName::EcdsaP384Sha384, P384_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::EcdsaP384Sha384(_)));

    let sk = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
    assert!(matches!(sk, SecretKey::Ed25519(_)));
    let pk = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::Ed25519(_)));
  }

  #[cfg(feature = "rsa-signature")]
  #[test]
  fn test_from_pem_rsa() {
    let sk = SecretKey::from_pem(&AlgorithmName::RsaV1_5Sha256, RSA2048_SECRET_KEY).unwrap();
    assert!(matches!(sk, SecretKey::RsaV1_5Sha256(_)));
    let pk = PublicKey::from_pem(&AlgorithmName::RsaV1_5Sha256, RSA2048_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::RsaV1_5Sha256(_)));

    let sk = SecretKey::from_pem(&AlgorithmName::RsaPssSha512, RSA2048_SECRET_KEY).unwrap();
    assert!(matches!(sk, SecretKey::RsaPssSha512(_)));
    let pk = PublicKey::from_pem(&AlgorithmName::RsaPssSha512, RSA2048_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::RsaPssSha512(_)));
  }

  #[test]
  fn test_sign_verify() {
    use super::super::{SigningKey, VerifyingKey};
    let sk = SecretKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());

    let sk = SecretKey::from_pem(&AlgorithmName::EcdsaP384Sha384, P384_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(&AlgorithmName::EcdsaP384Sha384, P384_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());

    let sk = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());
  }

  #[cfg(feature = "rsa-signature")]
  #[test]
  fn test_sign_verify_rsa() {
    use super::super::{SigningKey, VerifyingKey};
    let sk = SecretKey::from_pem(&AlgorithmName::RsaV1_5Sha256, RSA2048_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(&AlgorithmName::RsaV1_5Sha256, RSA2048_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());

    let sk = SecretKey::from_pem(&AlgorithmName::RsaPssSha512, RSA2048_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(&AlgorithmName::RsaPssSha512, RSA2048_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());
  }

  #[test]
  fn test_kid() -> HttpSigResult<()> {
    use super::super::VerifyingKey;
    let sk = SecretKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_SECRET_KEY)?;
    let pk = PublicKey::from_pem(&AlgorithmName::EcdsaP256Sha256, P256_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "k34r3Nqfak67bhJSXTjTRo5tCIr1Bsre1cPoJ3LJ9xE=");

    let sk = SecretKey::from_pem(&AlgorithmName::EcdsaP384Sha384, P384_SECRET_KEY)?;
    let pk = PublicKey::from_pem(&AlgorithmName::EcdsaP384Sha384, P384_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "JluSJKLaQsbGcgg1Ves4FfP/Kf7qS11RT88TvU0eNSo=");

    let sk = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY)?;
    let pk = PublicKey::from_pem(&AlgorithmName::Ed25519, EDDSA_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=");
    Ok(())
  }

  #[cfg(feature = "rsa-signature")]
  #[test]
  fn test_kid_rsa() -> HttpSigResult<()> {
    use super::super::VerifyingKey;
    let sk = SecretKey::from_pem(&AlgorithmName::RsaV1_5Sha256, RSA2048_SECRET_KEY)?;
    let pk = PublicKey::from_pem(&AlgorithmName::RsaV1_5Sha256, RSA2048_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "NoJFUyf2XUdhrTK66RlrGEemIlr1tOScYVeNVCv+5Ns=");

    let sk = SecretKey::from_pem(&AlgorithmName::RsaPssSha512, RSA2048_SECRET_KEY)?;
    let pk = PublicKey::from_pem(&AlgorithmName::RsaPssSha512, RSA2048_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "NoJFUyf2XUdhrTK66RlrGEemIlr1tOScYVeNVCv+5Ns="); // same as above nothing changes for RSA
    Ok(())
  }
}
