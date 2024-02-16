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

#[allow(non_upper_case_globals, dead_code)]
/// Algorithm OIDs
mod algorithm_oids {
  /// OID for `id-ecPublicKey`, if you're curious
  pub const EC: &str = "1.2.840.10045.2.1";
  /// OID for `id-Ed25519`, if you're curious
  pub const Ed25519: &str = "1.3.101.112";
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
/// Secret key for http signature
/// Name conventions follow [the IETF draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-6.2.2)
pub enum SecretKey {
  /// ecdsa-p384-sha384
  EcdsaP384Sha384(EcSecretKey<NistP384>),
  /// ecdsa-p256-sha256
  EcdsaP256Sha256(EcSecretKey<NistP256>),
  /// ed25519
  Ed25519(Ed25519SecretKey),
}

impl SecretKey {
  /// parse der
  /// Derive secret key from der bytes
  pub fn from_der(der: &[u8]) -> HttpSigResult<Self> {
    let pki = PrivateKeyInfo::from_der(der).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;

    match pki.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        debug!("Read EC private key");
        let param = pki
          .algorithm
          .parameters_oid()
          .map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
        let sk_bytes = sec1::EcPrivateKey::try_from(pki.private_key)
          .map_err(|e| HttpSigError::ParsePrivateKeyError(format!("Error decoding EcPrivateKey: {e}")))?
          .private_key;
        match param.to_string().as_ref() {
          params_oids::Secp256r1 => {
            let sk =
              p256::SecretKey::from_bytes(sk_bytes.into()).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
            Ok(Self::EcdsaP256Sha256(sk))
          }
          params_oids::Secp384r1 => {
            let sk =
              p384::SecretKey::from_bytes(sk_bytes.into()).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
            Ok(Self::EcdsaP384Sha384(sk))
          }
          _ => Err(HttpSigError::ParsePrivateKeyError("Unsupported curve".to_string())),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        debug!("Read Ed25519 private key");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&pki.private_key[2..]);
        let sk = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed)).sk;
        Ok(Self::Ed25519(sk))
      }
      _ => Err(HttpSigError::ParsePrivateKeyError(
        "Unsupported algorithm that supports PEM format keys".to_string(),
      )),
    }
  }

  /// Derive secret key from pem string
  pub fn from_pem(pem: &str) -> HttpSigResult<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;
    if tag != "PRIVATE KEY" {
      return Err(HttpSigError::ParsePrivateKeyError("Invalid tag".to_string()));
    };
    Self::from_der(doc.as_bytes())
  }

  /// Get public key from secret key
  pub fn public_key(&self) -> PublicKey {
    match &self {
      Self::EcdsaP256Sha256(key) => PublicKey::EcdsaP256Sha256(key.public_key()),
      Self::EcdsaP384Sha384(key) => PublicKey::EcdsaP384Sha384(key.public_key()),
      Self::Ed25519(key) => PublicKey::Ed25519(key.public_key()),
    }
  }
}

impl super::SigningKey for SecretKey {
  /// Sign data
  fn sign(&self, data: &[u8]) -> HttpSigResult<Vec<u8>> {
    match &self {
      Self::EcdsaP256Sha256(sk) => {
        let sk = ecdsa::SigningKey::from(sk);
        let mut digest = <Sha256 as Digest>::new();
        digest.update(data);
        let sig: ecdsa::Signature<NistP256> = sk.sign_digest(digest);
        Ok(sig.to_bytes().to_vec())
      }
      Self::EcdsaP384Sha384(sk) => {
        let sk = ecdsa::SigningKey::from(sk);
        let mut digest = <Sha384 as Digest>::new();
        digest.update(data);
        let sig: ecdsa::Signature<NistP384> = sk.sign_digest(digest);
        Ok(sig.to_bytes().to_vec())
      }
      Self::Ed25519(sk) => {
        let sig = sk.sign(data, Some(ed25519_compact::Noise::default()));
        Ok(sig.as_ref().to_vec())
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
/// Public key for http signature, only for asymmetric algorithm
/// Name conventions follow [the IETF draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-6.2.2)
pub enum PublicKey {
  /// ecdsa-p256-sha256
  EcdsaP256Sha256(EcPublicKey<NistP256>),
  /// ecdsa-p384-sha384
  EcdsaP384Sha384(EcPublicKey<NistP384>),
  /// ed25519
  Ed25519(Ed25519PublicKey),
}

impl PublicKey {
  #[allow(dead_code)]
  /// Convert from pem string
  pub fn from_pem(pem: &str) -> HttpSigResult<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
    if tag != "PUBLIC KEY" {
      return Err(HttpSigError::ParsePublicKeyError("Invalid tag".to_string()));
    };

    let spki_ref = SubjectPublicKeyInfoRef::from_der(doc.as_bytes())
      .map_err(|e| HttpSigError::ParsePublicKeyError(format!("Error decoding SubjectPublicKeyInfo: {e}").to_string()))?;
    match spki_ref.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        let param = spki_ref
          .algorithm
          .parameters_oid()
          .map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        let public_key = spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(HttpSigError::ParsePublicKeyError("Invalid public key".to_string()))?;
        match param.to_string().as_ref() {
          params_oids::Secp256r1 => {
            let pk = EcPublicKey::<NistP256>::from_sec1_bytes(public_key)
              .map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
            Ok(Self::EcdsaP256Sha256(pk))
          }
          params_oids::Secp384r1 => {
            let pk = EcPublicKey::<NistP384>::from_sec1_bytes(public_key)
              .map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
            Ok(Self::EcdsaP384Sha384(pk))
          }
          _ => Err(HttpSigError::ParsePublicKeyError("Unsupported curve".to_string())),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        let public_key = spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(HttpSigError::ParsePublicKeyError("Invalid public key".to_string()))?;
        let pk =
          ed25519_compact::PublicKey::from_slice(public_key).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
        Ok(Self::Ed25519(pk))
      }
      _ => Err(HttpSigError::ParsePublicKeyError(
        "Unsupported algorithm that supports PEM format keys".to_string(),
      )),
    }
  }
}

impl super::VerifyingKey for PublicKey {
  /// Verify signature
  fn verify(&self, data: &[u8], signature: &[u8]) -> HttpSigResult<()> {
    match self {
      Self::EcdsaP256Sha256(pk) => {
        let signature = ecdsa::Signature::<NistP256>::from_bytes(signature.into())
          .map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        let vk = ecdsa::VerifyingKey::from(pk);
        let mut digest = <Sha256 as Digest>::new();
        digest.update(data);
        vk.verify_digest(digest, &signature)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
      Self::EcdsaP384Sha384(pk) => {
        let signature = ecdsa::Signature::<NistP384>::from_bytes(signature.into())
          .map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        let vk = ecdsa::VerifyingKey::from(pk);
        let mut digest = <Sha384 as Digest>::new();
        digest.update(data);
        vk.verify_digest(digest, &signature)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
      Self::Ed25519(pk) => {
        let sig =
          ed25519_compact::Signature::from_slice(signature).map_err(|e| HttpSigError::ParseSignatureError(e.to_string()))?;
        pk.verify(data, &sig)
          .map_err(|e| HttpSigError::InvalidSignature(e.to_string()))
      }
    }
  }

  /// Create key id
  fn key_id(&self) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let bytes = match self {
      Self::EcdsaP256Sha256(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
      Self::EcdsaP384Sha384(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
      Self::Ed25519(vk) => vk.as_ref().to_vec(),
    };
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
  }

  /// Get the algorithm name
  fn alg(&self) -> AlgorithmName {
    match self {
      Self::EcdsaP256Sha256(_) => AlgorithmName::EcdsaP256Sha256,
      Self::EcdsaP384Sha384(_) => AlgorithmName::EcdsaP384Sha384,
      Self::Ed25519(_) => AlgorithmName::Ed25519,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::matches;

  const P256_SECERT_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
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
  const P384_SECERT_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
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

  #[test]
  fn test_from_pem() {
    let sk = SecretKey::from_pem(P256_SECERT_KEY).unwrap();
    assert!(matches!(sk, SecretKey::EcdsaP256Sha256(_)));
    let pk = PublicKey::from_pem(P256_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::EcdsaP256Sha256(_)));

    let sk = SecretKey::from_pem(P384_SECERT_KEY).unwrap();
    assert!(matches!(sk, SecretKey::EcdsaP384Sha384(_)));
    let pk = PublicKey::from_pem(P384_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::EcdsaP384Sha384(_)));

    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    assert!(matches!(sk, SecretKey::Ed25519(_)));
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::Ed25519(_)));
  }

  #[test]
  fn test_sign_verify() {
    use super::super::{SigningKey, VerifyingKey};
    let sk = SecretKey::from_pem(P256_SECERT_KEY).unwrap();
    let pk = PublicKey::from_pem(P256_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());

    let sk = SecretKey::from_pem(P384_SECERT_KEY).unwrap();
    let pk = PublicKey::from_pem(P384_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());

    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    let data = b"hello world";
    let signature = sk.sign(data).unwrap();
    pk.verify(data, &signature).unwrap();
    assert!(pk.verify(b"hello", &signature).is_err());
  }

  #[test]
  fn test_kid() -> HttpSigResult<()> {
    use super::super::VerifyingKey;
    let sk = SecretKey::from_pem(P256_SECERT_KEY)?;
    let pk = PublicKey::from_pem(P256_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "k34r3Nqfak67bhJSXTjTRo5tCIr1Bsre1cPoJ3LJ9xE");

    let sk = SecretKey::from_pem(P384_SECERT_KEY)?;
    let pk = PublicKey::from_pem(P384_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "JluSJKLaQsbGcgg1Ves4FfP_Kf7qS11RT88TvU0eNSo");

    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY)?;
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is");
    Ok(())
  }
}
