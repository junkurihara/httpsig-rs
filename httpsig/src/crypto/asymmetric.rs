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
}

impl SecretKey {
  /// from plain bytes
  pub fn from_bytes(alg: AlgorithmName, bytes: &[u8]) -> HttpSigResult<Self> {
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
      _ => Err(HttpSigError::ParsePrivateKeyError("Unsupported algorithm".to_string())),
    }
  }
  /// parse der
  /// Derive secret key from der bytes
  pub fn from_der(der: &[u8]) -> HttpSigResult<Self> {
    let pki = PrivateKeyInfo::from_der(der).map_err(|e| HttpSigError::ParsePrivateKeyError(e.to_string()))?;

    let (algorithm_name, sk_bytes) = match pki.algorithm.oid.to_string().as_ref() {
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
        let sk_bytes = sec1::EcPrivateKey::try_from(pki.private_key)
          .map_err(|e| HttpSigError::ParsePrivateKeyError(format!("Error decoding EcPrivateKey: {e}")))?
          .private_key;
        (algorithm_name, sk_bytes)
      }
      // ed25519
      algorithm_oids::Ed25519 => (AlgorithmName::Ed25519, &pki.private_key[2..]),
      _ => return Err(HttpSigError::ParsePrivateKeyError("Unsupported algorithm".to_string())),
    };
    let sk = Self::from_bytes(algorithm_name, sk_bytes)?;
    Ok(sk)
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
}

impl PublicKey {
  /// from plain bytes
  pub fn from_bytes(alg: AlgorithmName, bytes: &[u8]) -> HttpSigResult<Self> {
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
      _ => Err(HttpSigError::ParsePublicKeyError("Unsupported algorithm".to_string())),
    }
  }

  #[allow(dead_code)]
  /// Convert from pem string
  pub fn from_pem(pem: &str) -> HttpSigResult<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| HttpSigError::ParsePublicKeyError(e.to_string()))?;
    if tag != "PUBLIC KEY" {
      return Err(HttpSigError::ParsePublicKeyError("Invalid tag".to_string()));
    };

    let spki_ref = SubjectPublicKeyInfoRef::from_der(doc.as_bytes())
      .map_err(|e| HttpSigError::ParsePublicKeyError(format!("Error decoding SubjectPublicKeyInfo: {e}").to_string()))?;

    let (algorithm_name, pk_bytes) = match spki_ref.algorithm.oid.to_string().as_ref() {
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
        let pk_bytes = spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(HttpSigError::ParsePublicKeyError("Invalid public key".to_string()))?;
        (algorithm_name, pk_bytes)
      }
      // ed25519
      algorithm_oids::Ed25519 => (
        AlgorithmName::Ed25519,
        spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(HttpSigError::ParsePublicKeyError("Invalid public key".to_string()))?,
      ),
      _ => return Err(HttpSigError::ParsePublicKeyError("Unsupported algorithm".to_string())),
    };
    Self::from_bytes(algorithm_name, pk_bytes)
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
  use p256::elliptic_curve::group::GroupEncoding;

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
  fn test_from_bytes() {
    let ed25519_kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::default());
    let ed25519_sk = ed25519_kp.sk.seed().to_vec();
    let ed25519_pk = ed25519_kp.pk.as_ref();
    let sk = SecretKey::from_bytes(AlgorithmName::Ed25519, &ed25519_sk).unwrap();
    assert!(matches!(sk, SecretKey::Ed25519(_)));
    let pk = PublicKey::from_bytes(AlgorithmName::Ed25519, ed25519_pk).unwrap();
    assert!(matches!(pk, PublicKey::Ed25519(_)));

    let es256_sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let es256_pk = es256_sk.verifying_key();
    let sk = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, es256_sk.to_bytes().as_ref()).unwrap();
    assert!(matches!(sk, SecretKey::EcdsaP256Sha256(_)));
    let pk_bytes = es256_pk.as_affine().to_bytes();
    let pk = PublicKey::from_bytes(AlgorithmName::EcdsaP256Sha256, pk_bytes.as_slice()).unwrap();
    assert!(matches!(pk, PublicKey::EcdsaP256Sha256(_)));
  }

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
