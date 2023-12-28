use anyhow::{anyhow, bail, ensure, Result};
use ecdsa::{
  elliptic_curve::{sec1::ToEncodedPoint, PublicKey as EcPublicKey, SecretKey as EcSecretKey},
  signature::{DigestSigner, DigestVerifier},
};
use ed25519_compact::{PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use p256::NistP256;
use pkcs8::{der::Decode, Document, PrivateKeyInfo};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;
use tracing::debug;

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
  // Example parameters value: OID for the NIST P-256 elliptic curve.
  pub const Prime256v1: &str = "1.2.840.10045.3.1.7";
}

/* -------------------------------- */
/// Secret key for http signature
/// Name conventions follow [the IETF draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-6.2.2)
pub enum SecretKey {
  /// ecdsa-p256
  EcdsaP256Sha256(EcSecretKey<NistP256>),
  /// ed25519
  Ed25519(Ed25519SecretKey),
}

impl SecretKey {
  /// Derive secret key from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| anyhow!("Error decoding private key: {}", e))?;
    ensure!(tag == "PRIVATE KEY", "Invalid tag");

    let pki = PrivateKeyInfo::from_der(doc.as_bytes()).map_err(|e| anyhow!("Error decoding private key: {}", e))?;

    match pki.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        debug!("Read EC private key");
        let param = pki
          .algorithm
          .parameters_oid()
          .map_err(|e| anyhow!("Error decoding private key: {}", e))?;
        match param.to_string().as_ref() {
          params_oids::Prime256v1 => {
            let sk_bytes = sec1::EcPrivateKey::try_from(pki.private_key)
              .map_err(|e| anyhow!("Error decoding EcPrivateKey: {e}"))?
              .private_key;
            let sk =
              p256::SecretKey::from_bytes(sk_bytes.into()).map_err(|e| anyhow!("Error decoding private key: {}", e))?;
            Ok(Self::EcdsaP256Sha256(sk))
          }
          _ => bail!("Unsupported curve"),
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
      _ => bail!("Unsupported algorithm"),
    }
  }

  /// Sign data
  pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
    match &self {
      Self::EcdsaP256Sha256(sk) => {
        let sk = ecdsa::SigningKey::from(sk);
        let mut digest = Sha256::default();
        digest.update(data);
        let sig: ecdsa::Signature<NistP256> = sk.sign_digest(digest);
        Ok(sig.to_bytes().to_vec())
      }
      Self::Ed25519(sk) => {
        let sig = sk.sign(data, Some(ed25519_compact::Noise::default()));
        Ok(sig.as_ref().to_vec())
      }
    }
  }

  /// Get public key from secret key
  pub fn public_key(&self) -> PublicKey {
    match &self {
      Self::EcdsaP256Sha256(key) => PublicKey::EcdsaP256Sha256(key.public_key()),
      Self::Ed25519(key) => PublicKey::Ed25519(key.public_key()),
    }
  }
}

/* -------------------------------- */
/// Public key for http signature, only for asymmetric algorithm
/// Name conventions follow [the IETF draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-6.2.2)
pub enum PublicKey {
  /// ecdsa-p256-sha256
  EcdsaP256Sha256(EcPublicKey<NistP256>),
  /// ed25519
  Ed25519(Ed25519PublicKey),
}

impl PublicKey {
  #[allow(dead_code)]
  /// Convert from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| anyhow!("Error decoding public key: {}", e))?;
    ensure!(tag == "PUBLIC KEY", "Invalid tag");
    let spki_ref =
      SubjectPublicKeyInfoRef::from_der(doc.as_bytes()).map_err(|e| anyhow!("Error decoding public key: {}", e))?;
    match spki_ref.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        let param = spki_ref
          .algorithm
          .parameters_oid()
          .map_err(|e| anyhow!("Error decoding public key: {}", e))?;
        match param.to_string().as_ref() {
          // prime256v1 = es256
          params_oids::Prime256v1 => {
            let public_key = spki_ref
              .subject_public_key
              .as_bytes()
              .ok_or(anyhow!("Invalid public key"))?;
            let pk = EcPublicKey::<NistP256>::from_sec1_bytes(public_key)
              .map_err(|e| anyhow!("Error decoding public key: {}", e))?;
            Ok(Self::EcdsaP256Sha256(pk))
          }
          _ => bail!("Unsupported curve"),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        let public_key = spki_ref
          .subject_public_key
          .as_bytes()
          .ok_or(anyhow!("Invalid public key"))?;
        let pk = ed25519_compact::PublicKey::from_slice(public_key)
          .map_err(|e| anyhow!("Error decoding public key: {}", e))?;
        Ok(Self::Ed25519(pk))
      }
      _ => bail!("Unsupported algorithm"),
    }
  }

  /// Verify signature
  pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
    match self {
      Self::EcdsaP256Sha256(pk) => {
        let signature = ecdsa::Signature::<NistP256>::from_bytes(signature.into())
          .map_err(|e| anyhow!("Error decoding signature: {}", e))?;
        let vk = ecdsa::VerifyingKey::from(pk);
        let mut digest = Sha256::default();
        digest.update(data);
        vk.verify_digest(digest, &signature)
          .map_err(|e| anyhow!("Error verifying signature: {}", e))
      }
      Self::Ed25519(pk) => {
        let sig =
          ed25519_compact::Signature::from_slice(signature).map_err(|e| anyhow!("Error decoding signature: {}", e))?;
        pk.verify(data, &sig)
          .map_err(|e| anyhow!("Error verifying signature: {}", e))
      }
    }
  }

  /// Create key id
  pub fn key_id(&self) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let bytes = match self {
      Self::EcdsaP256Sha256(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
      Self::Ed25519(vk) => vk.as_ref().to_vec(),
    };
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::matches;

  const P256_SECERT_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv7zxW56ojrWwmSo1\n4uOdbVhUfj9Jd+5aZIB9u8gtWnihRANCAARGYsMe0CT6pIypwRvoJlLNs4+cTh2K\nL7fUNb5i6WbKxkpAoO+6T3pMBG5Yw7+8NuGTvvtrZAXduA2giPxQ8zCf\n-----END PRIVATE KEY-----";
  const P256_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERmLDHtAk+qSMqcEb6CZSzbOPnE4d\nii+31DW+YulmysZKQKDvuk96TARuWMO/vDbhk777a2QF3bgNoIj8UPMwnw==\n-----END PUBLIC KEY-----\n";

  const EDDSA_SECRET_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C\n-----END PRIVATE KEY-----";
  const EDDSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=\n-----END PUBLIC KEY-----\n";

  #[test]
  fn test_from_pem() {
    let sk = SecretKey::from_pem(P256_SECERT_KEY).unwrap();
    assert!(matches!(sk, SecretKey::EcdsaP256Sha256(_)));
    let pk = PublicKey::from_pem(P256_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::EcdsaP256Sha256(_)));

    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    assert!(matches!(sk, SecretKey::Ed25519(_)));
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap();
    assert!(matches!(pk, PublicKey::Ed25519(_)));
  }

  #[test]
  fn test_sign_verify() {
    let sk = SecretKey::from_pem(P256_SECERT_KEY).unwrap();
    let pk = PublicKey::from_pem(P256_PUBLIC_KEY).unwrap();
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
  fn test_kid() -> Result<()> {
    let sk = SecretKey::from_pem(P256_SECERT_KEY)?;
    let pk = PublicKey::from_pem(P256_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "k34r3Nqfak67bhJSXTjTRo5tCIr1Bsre1cPoJ3LJ9xE");

    let sk = SecretKey::from_pem(EDDSA_SECRET_KEY)?;
    let pk = PublicKey::from_pem(EDDSA_PUBLIC_KEY)?;
    assert_eq!(sk.public_key().key_id(), pk.key_id());
    assert_eq!(pk.key_id(), "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is");
    Ok(())
  }
}
