use crate::{
  crypto::{AlgorithmName, SigningKey},
  error::{HttpSigError, HttpSigResult},
  message_component::HttpMessageComponentId,
  trace::*,
  util::has_unique_elements,
};
use base64::{engine::general_purpose, Engine as _};
use compact_str::{CompactString, ToCompactString};
use rand::RngExt;
use sfv::{FieldType, InnerList, ListEntry, Parser};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_DURATION: u64 = 300;

/* ---------------------------------------- */
#[derive(Debug, Clone, Default)]
/// Struct defining Http message signature parameters
/// https://datatracker.ietf.org/doc/html/rfc9421#name-signature-parameters
pub struct HttpSignatureParams {
  /// created unix timestamp.
  pub created: Option<u64>,
  /// signature expires unix timestamp.
  pub expires: Option<u64>,
  /// nonce
  pub nonce: Option<CompactString>,
  /// algorithm name
  pub alg: Option<CompactString>,
  /// key id.
  pub keyid: Option<CompactString>,
  /// tag
  pub tag: Option<CompactString>,
  /// covered component vector string: ordered message components, i.e., string of http_fields and derived_components
  pub covered_components: Vec<HttpMessageComponentId>,
}

impl HttpSignatureParams {
  /// Create new HttpSignatureParams object for the given covered components only with `created`` current timestamp.
  pub fn try_new(covered_components: &[HttpMessageComponentId]) -> HttpSigResult<Self> {
    let created = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs();
    if !has_unique_elements(covered_components.iter()) {
      return Err(HttpSigError::InvalidSignatureParams(
        "duplicate covered component ids".into(),
      ));
    }

    Ok(Self {
      created: Some(created),
      covered_components: covered_components.to_vec(),
      ..Default::default()
    })
  }

  /// Set artificial `created` timestamp
  pub fn set_created(&mut self, created: u64) -> &mut Self {
    self.created = Some(created);
    self
  }

  /// Set `expires` timestamp
  pub fn set_expires(&mut self, expires: u64) -> &mut Self {
    self.expires = Some(expires);
    self
  }

  /// Set `nonce`
  pub fn set_nonce(&mut self, nonce: &str) -> &mut Self {
    self.nonce = Some(nonce.to_compact_string());
    self
  }

  /// Set `alg`
  pub fn set_alg(&mut self, alg: &AlgorithmName) -> &mut Self {
    self.alg = Some(alg.to_compact_string());
    self
  }

  /// Set `keyid`
  pub fn set_keyid(&mut self, keyid: &str) -> &mut Self {
    self.keyid = Some(keyid.to_compact_string());
    self
  }

  /// Set `tag`
  pub fn set_tag(&mut self, tag: &str) -> &mut Self {
    self.tag = Some(tag.to_compact_string());
    self
  }

  /// Set `keyid` and `alg` from the signing key
  pub fn set_key_info(&mut self, key: &impl SigningKey) -> &mut Self {
    #[cfg(feature = "key-id")]
    {
      self.keyid = Some(key.key_id().to_compact_string());
    }
    self.alg = Some(key.alg().to_compact_string());
    self
  }

  /// Set random nonce
  pub fn set_random_nonce(&mut self) -> &mut Self {
    let mut rng = rand::rng();
    let nonce = rng.random::<[u8; 32]>();
    // 32 bytes - 10 full 3-byte groups and 2 bytes, requiring zero padding till the full 11th group
    // Each 3-byte group base64-encoded as 4 byte group.
    const BUF_SIZE: usize = 11 * 4;
    let mut buf = CompactString::with_capacity(BUF_SIZE);
    // SAFETY: base64 encoding is valid UTF-8 encoding
    unsafe {
      general_purpose::STANDARD
        .encode_slice(nonce, buf.as_bytes_mut())
        .expect("fits in the buffer")
    };
    self.nonce = Some(buf);
    self
  }

  /// Set `expires` timestamp from the current timestamp
  pub fn set_expires_with_duration(&mut self, duration_secs: Option<u64>) -> &mut Self {
    assert!(self.created.is_some(), "created timestamp is not set");
    let duration_secs = duration_secs.unwrap_or(DEFAULT_DURATION);
    self.expires = Some(self.created.unwrap() + duration_secs);
    self
  }

  /// Check if the signature params is expired if `exp` field is present.
  /// If `exp` field is not present, it always returns false.
  pub fn is_expired(&self) -> bool {
    if let Some(exp) = self.expires {
      exp
        < SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .unwrap()
          .as_secs()
    } else {
      false
    }
  }
}

impl std::fmt::Display for HttpSignatureParams {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "(")?;
    let mut covered_components_iter = self.covered_components.iter();
    if let Some(component_id) = covered_components_iter.next() {
      write!(f, "{}", component_id)?;
    }
    for component_id in covered_components_iter {
      write!(f, " {}", component_id)?;
    }
    write!(f, ")")?;
    if let Some(created) = self.created {
      write!(f, ";created={}", created)?;
    }
    if let Some(expires) = self.expires {
      write!(f, ";expires={}", expires)?;
    }
    if let Some(nonce) = &self.nonce {
      write!(f, ";nonce=\"{}\"", nonce)?;
    }
    if let Some(alg) = &self.alg {
      write!(f, ";alg=\"{}\"", alg)?;
    }
    if let Some(key_id) = &self.keyid {
      write!(f, ";keyid=\"{}\"", key_id)?;
    }
    if let Some(tag) = &self.tag {
      write!(f, ";tag=\"{}\"", tag)?;
    }
    Ok(())
  }
}

impl TryFrom<&InnerList> for HttpSignatureParams {
  type Error = HttpSigError;

  /// Convert from InnerList to HttpSignatureParams
  fn try_from(inner_list_with_params: &InnerList) -> HttpSigResult<Self> {
    let covered_components = inner_list_with_params
      .items
      .iter()
      .map(|v| {
        HttpMessageComponentId::try_from(v.serialize().as_str())
        // v.serialize_value()
        //   .map_err(|e| HttpSigError::ParseSFVError(e.to_string()))
        //   .and_then(|v| HttpMessageComponentId::try_from(v.as_str()))
      })
      .collect::<Result<Vec<_>, _>>()?;

    if !has_unique_elements(covered_components.iter()) {
      return Err(HttpSigError::InvalidSignatureParams(
        "duplicate covered component ids".into(),
      ));
    }

    let mut params = Self {
      created: None,
      expires: None,
      nonce: None,
      alg: None,
      keyid: None,
      tag: None,
      covered_components,
    };

    for (key, bare_item) in inner_list_with_params.params.iter() {
      match key.as_str() {
        "created" => {
          params.created = bare_item
            .as_integer()
            .map(|v| v.try_into())
            .transpose()
            .map_err(|e: sfv::Error| HttpSigError::InvalidSignatureParams(e.to_string().into()))?
        }
        "expires" => {
          params.expires = bare_item
            .as_integer()
            .map(|v| v.try_into())
            .transpose()
            .map_err(|e: sfv::Error| HttpSigError::InvalidSignatureParams(e.to_string().into()))?
        }
        "nonce" => {
          params.nonce = bare_item
            .as_string()
            .map(|v| v.as_str().to_compact_string())
        }
        "alg" => {
          params.alg = bare_item
            .as_string()
            .map(|v| v.as_str().to_compact_string())
        }
        "keyid" => {
          params.keyid = bare_item
            .as_string()
            .map(|v| v.as_str().to_compact_string())
        }
        "tag" => {
          params.tag = bare_item
            .as_string()
            .map(|v| v.as_str().to_compact_string())
        }
        _ => {
          error!("Ignore unknown signature parameter: {}", key)
        }
      };
    }
    Ok(params)
  }
}

impl TryFrom<&ListEntry> for HttpSignatureParams {
  type Error = HttpSigError;
  /// Convert from ListEntry to HttpSignatureParams
  fn try_from(list: &ListEntry) -> HttpSigResult<Self> {
    let ListEntry::InnerList(inner_list_with_params) = list else {
      return Err(HttpSigError::InvalidSignatureParams(
        "an inner list is expected".into(),
      ));
    };
    inner_list_with_params.try_into()
  }
}

impl TryFrom<&str> for HttpSignatureParams {
  type Error = HttpSigError;
  /// Convert from string to HttpSignatureParams
  fn try_from(value: &str) -> HttpSigResult<Self> {
    let sfv_parsed: sfv::List = Parser::new(value).parse()?;
    // let sfv_parsed = Parser::parse_list(value.as_bytes()).map_err(|e| HttpSigError::ParseSFVError(e.to_string()))?;
    if let (1, Some(ListEntry::InnerList(single_list_param))) =
      (sfv_parsed.len(), sfv_parsed.first())
    {
      single_list_param.try_into()
    } else {
      Err(HttpSigError::InvalidSignatureParams(
        // multiple signatures per signature input header are handled on signature headers level
        "a single inner list is expected".into(),
      ))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[cfg(feature = "ed25519-signature")]
  use crate::crypto::SecretKey;
  #[cfg(feature = "ed25519-signature")]
  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  #[cfg(feature = "ed25519-signature")]
  const _EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
  #[cfg(feature = "ed25519-signature")]
  const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=";

  fn build_covered_components() -> Vec<HttpMessageComponentId> {
    vec![
      HttpMessageComponentId::try_from("@method").unwrap(),
      HttpMessageComponentId::try_from("@path").unwrap(),
      HttpMessageComponentId::try_from("@scheme").unwrap(),
      HttpMessageComponentId::try_from("@authority").unwrap(),
      HttpMessageComponentId::try_from("content-type").unwrap(),
      HttpMessageComponentId::try_from("date").unwrap(),
      HttpMessageComponentId::try_from("content-length").unwrap(),
    ]
  }

  #[test]
  fn test_try_new() {
    let params = HttpSignatureParams::try_new(&build_covered_components());
    assert!(params.is_ok());
    let params = params.unwrap();
    assert!(params.created.is_some());
    assert!(params.expires.is_none());
    assert!(params.nonce.is_none());
    assert!(params.alg.is_none());
    assert!(params.keyid.is_none());
    assert!(params.tag.is_none());
    assert_eq!(params.covered_components.len(), 7);
  }

  #[cfg(feature = "ed25519-signature")]
  #[test]
  fn test_set_key_info() {
    let mut params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    params.set_key_info(&SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap());
    assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_compact_string()));
    assert_eq!(params.alg, Some("ed25519".to_compact_string()));
  }

  #[test]
  fn test_set_duration() {
    let mut params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    params.set_expires_with_duration(Some(100));
    assert!(params.expires.is_some());
    assert_eq!(params.expires.unwrap(), params.created.unwrap() + 100);
    assert!(!params.is_expired());

    let created = params.created.unwrap();
    params.set_expires(created - 1);
    assert!(params.is_expired());
  }

  #[test]
  fn test_from_string_signature_params_without_param() {
    let value =
      r##"("@method" "@path" "@scheme" "@authority" "content-type" "date" "content-length")"##;
    let params = HttpSignatureParams::try_from(value);
    assert!(params.is_ok());
    let params = params.unwrap();
    assert!(params.created.is_none());
    assert!(params.expires.is_none());
    assert!(params.nonce.is_none());
    assert!(params.alg.is_none());
    assert!(params.keyid.is_none());
    assert!(params.tag.is_none());
    assert_eq!(params.covered_components.len(), 7);
  }

  #[cfg(feature = "ed25519-signature")]
  #[test]
  fn test_from_string_signature_params() {
    const SIGPARA: &str =
      r##";created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=""##;
    let values = vec![
      (
        r##""@method" "@path" "@scheme";req "@authority" "content-type";bs "date" "content-length""##,
        SIGPARA,
      ),
      (r##""##, SIGPARA),
    ];
    for (covered, sigpara) in values {
      let value = format!("({}){}", covered, sigpara);
      let params = HttpSignatureParams::try_from(value.as_str());
      assert!(params.is_ok());
      let params = params.unwrap();

      assert_eq!(params.created, Some(1704972031));
      assert_eq!(params.expires, None);
      assert_eq!(params.nonce, None);
      assert_eq!(params.alg, Some("ed25519".to_compact_string()));
      assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_compact_string()));
      assert_eq!(params.tag, None);
      let covered_components = covered
        .split(' ')
        .filter(|v| !v.is_empty())
        .map(|v| HttpMessageComponentId::try_from(v).unwrap())
        .collect::<Vec<_>>();
      assert_eq!(params.covered_components, covered_components);
      assert_eq!(params.to_string(), value);
    }
  }
}
