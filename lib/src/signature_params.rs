use crate::{
  crypto::{AlgorithmName, SigningKey},
  message_component::HttpMessageComponentId,
  trace::*,
  util::has_unique_elements,
};
use anyhow::{bail, ensure};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_DURATION: u64 = 300;

/* ---------------------------------------- */
#[derive(Debug, Clone, Default)]
/// Struct defining Http message signature parameters
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-signature-parameters
pub struct HttpSignatureParams {
  /// created unix timestamp.
  pub created: Option<u64>,
  /// signature expires unix timestamp.
  pub expires: Option<u64>,
  /// nonce
  pub nonce: Option<String>,
  /// algorithm name
  pub alg: Option<String>,
  /// key id.
  pub keyid: Option<String>,
  /// tag
  pub tag: Option<String>,
  /// covered component vector string: ordered message components, i.e., string of http_fields and derived_components
  pub covered_components: Vec<HttpMessageComponentId>,
}

impl HttpSignatureParams {
  /// Create new HttpSignatureParams object for the given covered components only with `created`` current timestamp.
  pub fn try_new(covered_components: &[HttpMessageComponentId]) -> anyhow::Result<Self> {
    let created = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    ensure!(
      has_unique_elements(covered_components.iter()),
      "duplicate covered component ids"
    );
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
    self.nonce = Some(nonce.to_string());
    self
  }

  /// Set `alg`
  pub fn set_alg(&mut self, alg: &AlgorithmName) -> &mut Self {
    self.alg = Some(alg.to_string());
    self
  }

  /// Set `keyid`
  pub fn set_keyid(&mut self, keyid: &str) -> &mut Self {
    self.keyid = Some(keyid.to_string());
    self
  }

  /// Set `tag`
  pub fn set_tag(&mut self, tag: &str) -> &mut Self {
    self.tag = Some(tag.to_string());
    self
  }

  /// Set `keyid` and `alg` from the signing key
  pub fn set_key_info(&mut self, key: &impl SigningKey) -> &mut Self {
    self.keyid = Some(key.key_id().to_string());
    self.alg = Some(key.alg().to_string());
    self
  }

  /// Set random nonce
  pub fn set_random_nonce(&mut self) -> &mut Self {
    let mut rng = rand::thread_rng();
    let nonce = rng.gen::<[u8; 32]>();
    self.nonce = Some(general_purpose::URL_SAFE_NO_PAD.encode(nonce));
    self
  }

  /// Set `expires` timestamp from the current timestamp
  pub fn set_expires_with_duration(&mut self, duration_secs: Option<u64>) -> &mut Self {
    assert!(self.created.is_some(), "created timestamp is not set");
    let duration_secs = duration_secs.unwrap_or(DEFAULT_DURATION);
    self.expires = Some(self.created.unwrap() + duration_secs);
    self
  }
}

impl std::fmt::Display for HttpSignatureParams {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let joined = self.covered_components.iter().fold("".to_string(), |acc, v| {
      if acc.is_empty() {
        v.to_string()
      } else {
        format!("{acc} {v}")
      }
    });
    let mut s: String = format!("({})", joined);
    if self.created.is_some() {
      s.push_str(&format!(";created={}", self.created.unwrap()));
    }
    if self.expires.is_some() {
      s.push_str(&format!(";expires={}", self.expires.unwrap()));
    }
    if self.nonce.is_some() {
      s.push_str(&format!(";nonce=\"{}\"", self.nonce.as_ref().unwrap()));
    }
    if self.alg.is_some() {
      s.push_str(&format!(";alg=\"{}\"", self.alg.as_ref().unwrap()));
    }
    if self.keyid.is_some() {
      s.push_str(&format!(";keyid=\"{}\"", self.keyid.as_ref().unwrap()));
    }
    if self.tag.is_some() {
      s.push_str(&format!(";tag=\"{}\"", self.tag.as_ref().unwrap()));
    }
    write!(f, "{}", s)
  }
}

impl TryFrom<&str> for HttpSignatureParams {
  type Error = anyhow::Error;
  fn try_from(value: &str) -> anyhow::Result<Self> {
    // first extract string inside `()`
    if !(value.starts_with('(') && value.contains(')')) {
      bail!("Invalid message components: {}", value);
    }
    let (inner_list, input_param) = value[1..].split_once(')').map(|(k, v)| (k.trim(), v.trim())).unwrap();
    let covered_components = inner_list
      .split(' ')
      .filter(|v| !v.is_empty())
      .map(HttpMessageComponentId::try_from)
      .collect::<Vec<_>>();
    ensure!(
      covered_components.iter().all(|v| v.is_ok()),
      "Invalid message component ids: {value}"
    );
    ensure!(
      has_unique_elements(covered_components.iter().map(|v| v.as_ref().unwrap())),
      "duplicate covered component ids: {value}"
    );
    let covered_components = covered_components
      .into_iter()
      .map(|v| v.unwrap())
      .collect::<Vec<HttpMessageComponentId>>();

    let mut params = Self {
      created: None,
      expires: None,
      nonce: None,
      alg: None,
      keyid: None,
      tag: None,
      covered_components,
    };

    // then extract signature parameters
    if !input_param.is_empty() {
      if !input_param.starts_with(';') {
        anyhow::bail!("Invalid signature parameter: {}", input_param);
      };
      input_param[1..].split(';').for_each(|param| {
        let mut param_iter = param.split('=');
        let key = param_iter.next().unwrap();
        let value = param_iter.next().unwrap();
        match key {
          "created" => params.created = Some(value.parse::<u64>().unwrap()),
          "expires" => params.expires = Some(value.parse::<u64>().unwrap()),
          "nonce" => params.nonce = Some(value[1..value.len() - 1].to_string()),
          "alg" => params.alg = Some(value[1..value.len() - 1].to_string()),
          "keyid" => params.keyid = Some(value[1..value.len() - 1].to_string()),
          "tag" => params.tag = Some(value[1..value.len() - 1].to_string()),
          _ => {
            error!("Ignore invalid signature parameter: {}", key)
          }
        }
      });
    };

    Ok(params)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::SecretKey;
  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  const _EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
  const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is";

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

  #[test]
  fn test_set_key_info() {
    let mut params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    params.set_key_info(&SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap());
    assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
    assert_eq!(params.alg, Some("ed25519".to_string()));
  }

  #[test]
  fn test_set_duration() {
    let mut params = HttpSignatureParams::try_new(&build_covered_components()).unwrap();
    params.set_expires_with_duration(Some(100));
    assert!(params.expires.is_some());
    assert_eq!(params.expires.unwrap(), params.created.unwrap() + 100);
  }

  #[test]
  fn test_from_string_signature_params_without_param() {
    let value = r##"("@method" "@path" "@scheme" "@authority" "content-type" "date" "content-length")"##;
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

  #[test]
  fn test_from_string_signature_params() {
    const SIGPARA: &str = r##";created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is""##;
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
      assert_eq!(params.alg, Some("ed25519".to_string()));
      assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
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
