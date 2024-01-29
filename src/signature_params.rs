use crate::{
  crypto::VerifyingKey,
  message_component::{HttpMessageComponentId, HttpMessageComponentName},
  util::has_unique_elements,
};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_EXPIRES_IN: u64 = 300;

/* ---------------------------------------- */
#[derive(Debug, Clone)]
/// Struct defining Http message signature parameters
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-signature-parameters
pub struct HttpSignatureParams {
  /// created unix timestamp.
  pub(crate) created: Option<u64>,
  /// signature expires unix timestamp.
  pub(crate) expires: Option<u64>,
  /// nonce
  pub(crate) nonce: Option<String>,
  /// algorithm name
  pub(crate) alg: Option<String>,
  /// key id.
  pub(crate) keyid: Option<String>,
  /// tag
  pub(crate) tag: Option<String>,
  /// covered component vector string: ordered message components, i.e., string of http_fields and derived_components
  pub(crate) covered_components: Vec<HttpMessageComponentId>,
}

impl std::fmt::Display for HttpSignatureParams {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let joined = self.covered_components.iter().fold("".to_string(), |acc, v| {
      if acc.is_empty() {
        v.to_string()
      } else {
        format!("{} {}", acc, v.to_string())
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
      anyhow::bail!("Invalid message components: {}", value);
    }
    let mut iter = value[1..].split(')');
    let covered_components = iter
      .next()
      .unwrap()
      .split(' ')
      .filter(|v| !v.is_empty())
      .map(|v| HttpMessageComponentId::try_from(v))
      .collect::<Vec<_>>();
    anyhow::ensure!(
      covered_components.iter().all(|v| v.is_ok()),
      "Invalid message components: {}",
      value
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
    if let Some(remains) = iter.next() {
      if !remains.starts_with(';') {
        anyhow::bail!("Invalid signature parameter: {}", remains);
      };
      remains[1..].split(';').for_each(|param| {
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
          _ => panic!("Invalid signature parameter: {}", key),
        }
      });
    };

    Ok(params)
  }
}

/* ---------------------------------------- */

// /// Builder of Http message signature parameters
// /// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-signature-parameters
// pub struct HttpSignatureParamsBuilder {
//   /// created unix timestamp. if none and set_created = false, use current timestamp
//   created: Option<u64>,
//   /// if true, `created` is set.
//   set_created: bool,
//   /// signature expires in `expires_in` seconds after `created`, i.e., `expires` is set to be `created + expires_in`.
//   /// if none and contains_expires = true, use DEFAULT_EXPIRES_IN seconds
//   expires_in: Option<u64>,
//   /// if true, `expires` is set to be `created + expires_in`.
//   set_expires: bool,
//   /// if none and contains_nonce = true, use random nonce, i.e., artificial nonce is set if Some<String> and contains_nonce = true.
//   nonce: Option<String>,
//   /// if true, `nonce` is set.
//   set_nonce: bool,
//   /// algorithm name
//   alg: Option<String>,
//   /// key id.
//   keyid: Option<String>,
//   /// tag
//   tag: Option<String>,
//   /// derived components and http field component ike `date`, `content-type`, `content-length`, etc.
//   /// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2
//   covered_components: Vec<HttpMessageComponentName>,
// }

// impl Default for HttpSignatureParamsBuilder {
//   fn default() -> Self {
//     Self {
//       created: None,
//       set_created: true,
//       expires_in: Some(DEFAULT_EXPIRES_IN),
//       set_expires: false,
//       nonce: None,
//       set_nonce: false,
//       alg: None,
//       keyid: None,
//       tag: None,
//       covered_components: vec![],
//     }
//   }
// }

// impl HttpSignatureParamsBuilder {
//   /// Set key id
//   pub fn key_id(&mut self, keyid: &str) -> &mut Self {
//     self.keyid = Some(keyid.to_string());
//     self
//   }
//   /// set algorithm
//   pub fn algorithm(&mut self, alg: &str) -> &mut Self {
//     self.alg = Some(alg.to_string());
//     self
//   }
//   /// Set keyid and alg from the key
//   pub fn key_info(&mut self, key: &impl VerifyingKey) {
//     self.keyid = Some(key.key_id().to_string());
//     self.alg = Some(key.alg().to_string());
//   }
//   /// Set artificial created
//   pub fn created(&mut self, created: u64) -> &mut Self {
//     self.created = Some(created);
//     self.set_created = true;
//     self
//   }
//   /// Set covered components
//   pub fn covered_message_component_ids(&mut self, components: &[&str]) {
//     self.covered_components = components.iter().map(|&c| HttpMessageComponentName::from(c)).collect();
//     assert!(has_unique_elements(self.covered_components.iter()))
//   }
//   /// Extend covered conmpoents
//   pub fn extend_covered_message_component_ids(&mut self, components: &[&str]) {
//     self
//       .covered_components
//       .extend(components.iter().map(|&c| HttpMessageComponentName::from(c)));
//     // check duplicates
//     assert!(has_unique_elements(self.covered_components.iter()))
//   }

//   /// Derive HttpSignatureParams object
//   pub fn build(&self) -> HttpSignatureParams {
//     let covered_components = self.covered_components.iter().map(|c| c.to_string()).collect::<Vec<String>>();
//     let created = if self.set_created {
//       if self.created.is_none() {
//         Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
//       } else {
//         self.created
//       }
//     } else {
//       None
//     };
//     let expires = if self.set_expires {
//       if self.expires_in.is_none() {
//         Some(created.unwrap() + DEFAULT_EXPIRES_IN)
//       } else {
//         created.map(|v| v + self.expires_in.unwrap())
//       }
//     } else {
//       None
//     };
//     let nonce = if self.set_nonce {
//       if self.nonce.is_none() {
//         // generate 32 bytes random nonce in base64url encoding
//         let mut rng = rand::thread_rng();
//         let nonce = rng.gen::<[u8; 32]>();
//         Some(general_purpose::URL_SAFE_NO_PAD.encode(nonce))
//       } else {
//         self.nonce.clone()
//       }
//     } else {
//       None
//     };

//     HttpSignatureParams {
//       created,
//       expires,
//       nonce,
//       alg: self.alg.clone(),
//       keyid: self.keyid.clone(),
//       tag: self.tag.clone(),
//       covered_components,
//     }
//   }
// }

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::PublicKey;
  const _EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
  const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is";

  // #[test]
  // fn test_set_key_info() {
  //   let mut params = HttpSignatureParamsBuilder::default();
  //   params.covered_message_component_ids(&["\"@method\"", "\"@path\";bs", "\"@authority\""]);
  //   let x = vec!["\"@method\"", "\"@path\";bs", "\"@authority\""]
  //     .into_iter()
  //     .map(HttpMessageComponentName::from)
  //     .collect::<Vec<_>>();
  //   assert_eq!(params.covered_components, x);
  //   params.key_info(&PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap());
  //   assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
  //   assert_eq!(params.alg, Some("ed25519".to_string()));
  // }

  // #[test]
  // fn test_http_signature_params() {
  //   let mut params = HttpSignatureParamsBuilder::default();
  //   params.covered_message_component_ids(&[
  //     "\"@method\"",
  //     "\"@path\";bs",
  //     "\"@authority\"",
  //     "\"@scheme\";req",
  //     "\"date\"",
  //     "\"content-type\";bs",
  //     "\"content-length\"",
  //   ]);
  //   params.key_info(&PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap());

  //   let params = params.build();
  //   assert!(params.created.is_some());
  //   assert!(params.expires.is_none());
  //   assert!(params.nonce.is_none());
  //   assert_eq!(params.alg, Some("ed25519".to_string()));
  //   assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
  //   assert_eq!(params.tag, None);

  //   assert!(params.covered_components.contains(&"\"@method\"".to_string()));
  //   // only `req` field param is allowed for derived components unlike general http fields
  //   // drops bs field param
  //   assert!(params.covered_components.contains(&"\"@path\"".to_string()));
  //   // req remains
  //   assert!(params.covered_components.contains(&"\"@scheme\";req".to_string()));

  //   assert!(params.covered_components.contains(&"\"@authority\"".to_string()));
  //   assert!(params.covered_components.contains(&"\"date\"".to_string()));
  //   assert!(params.covered_components.contains(&"\"content-type\";bs".to_string()));
  //   assert!(params.covered_components.contains(&"\"content-length\"".to_string()));

  //   // println!("{}", params);
  // }
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
