use crate::{crypto::VerifyingKey, trace::*};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use rustc_hash::FxHashSet as HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_EXPIRES_IN: u64 = 300;

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

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
/// Http field parameters that appends with `;` in the signature input
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#secion-2.1
enum HttpFieldParam {
  /// sf: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.1.1
  Sf,
  /// key: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.1.2
  /// This will be encoded to `;key="..."` in the signature input
  Key(String),
  /// bs: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.1.3
  Bs,
  // tr: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.1.4
  Tr,
  // req: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.4
  Req,
}

impl From<HttpFieldParam> for String {
  fn from(val: HttpFieldParam) -> Self {
    match val {
      HttpFieldParam::Sf => "sf".to_string(),
      HttpFieldParam::Key(val) => format!("key=\"{}\"", val),
      HttpFieldParam::Bs => "bs".to_string(),
      HttpFieldParam::Tr => "tr".to_string(),
      HttpFieldParam::Req => "req".to_string(),
    }
  }
}
impl From<&str> for HttpFieldParam {
  fn from(val: &str) -> Self {
    match val {
      "sf" => Self::Sf,
      "bs" => Self::Bs,
      "tr" => Self::Tr,
      "req" => Self::Req,
      _ => {
        if val.starts_with("key=\"") && val.ends_with('"') {
          Self::Key(val[5..val.len() - 1].to_string())
        } else {
          panic!("Invalid http field param: {}", val)
        }
      }
    }
  }
}

#[derive(PartialEq, Eq, Debug)]
struct HttpFieldParams(HashSet<HttpFieldParam>);
impl std::hash::Hash for HttpFieldParams {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    let mut params = self.0.iter().map(|v| v.clone().into()).collect::<Vec<String>>();
    params.sort();
    params.hash(state);
  }
}

#[derive(PartialEq, Eq, Clone, Hash, Debug)]
/// Derive components from http message, which is expressed as @method, @path, @authority, etc. in @signature-params
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-derived-components
enum HttpDerivedComponentInner {
  Method,
  TargetUri,
  Authority,
  Scheme,
  RequestTarget,
  Path,
  Query,
  QueryParam,
  Status,
}
impl AsRef<str> for HttpDerivedComponentInner {
  fn as_ref(&self) -> &str {
    match self {
      Self::Method => "\"@method\"",
      Self::TargetUri => "\"@target-uri\"",
      Self::Authority => "\"@authority\"",
      Self::Scheme => "\"@scheme\"",
      Self::RequestTarget => "\"@request-target\"",
      Self::Path => "\"@path\"",
      Self::Query => "\"@query\"",
      Self::QueryParam => "\"@query-param\"",
      Self::Status => "\"@status\"",
    }
  }
}
impl From<HttpDerivedComponentInner> for String {
  fn from(val: HttpDerivedComponentInner) -> Self {
    val.as_ref().to_string()
  }
}
impl From<&str> for HttpDerivedComponentInner {
  fn from(val: &str) -> Self {
    match val {
      "\"@method\"" => Self::Method,
      "\"@target-uri\"" => Self::TargetUri,
      "\"@authority\"" => Self::Authority,
      "\"@scheme\"" => Self::Scheme,
      "\"@request-target\"" => Self::RequestTarget,
      "\"@path\"" => Self::Path,
      "\"@query\"" => Self::Query,
      "\"@query-param\"" => Self::QueryParam,
      "\"@status\"" => Self::Status,
      _ => panic!("Invalid derived component: {}", val),
    }
  }
}

#[derive(PartialEq, Eq, Hash, Debug)]
/// Http derived component setting with optional parameters
struct HttpDerivedComponent {
  /// derived component
  component: HttpDerivedComponentInner,
  /// parameters
  params: HttpFieldParams,
}

impl From<&str> for HttpDerivedComponent {
  /// this feeds `"<derived-component>";<field-params>` format, e.g., `"@method";req`
  fn from(val: &str) -> Self {
    let mut iter = val.split(';');
    let component = iter.next().unwrap();
    // only `req` field param is allowed for derived components unlike general http fields
    let params = iter
      .map(HttpFieldParam::from)
      .filter(|v| matches!(v, HttpFieldParam::Req))
      .collect::<HashSet<_>>();
    Self {
      component: HttpDerivedComponentInner::from(component),
      params: HttpFieldParams(params),
    }
  }
}
impl std::fmt::Display for HttpDerivedComponent {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut s: String = self.component.clone().into();
    if !self.params.0.is_empty() {
      s.push(';');
      s.push_str(
        &self
          .params
          .0
          .iter()
          .map(|v| v.clone().into())
          .collect::<Vec<String>>()
          .join(";"),
      );
    }
    write!(f, "{}", s)
  }
}

#[derive(PartialEq, Eq, Hash, Debug)]
/// Http field setting with optional parameters
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-http-fields
struct HttpField {
  /// field name
  filed_name: String,
  /// parameters
  params: HttpFieldParams,
}

impl From<&str> for HttpField {
  /// this feeds `"<field-name>";<field-params>` format, e.g., `"example-header";bs`
  fn from(val: &str) -> Self {
    let mut iter = val.split(';');
    let field_name = iter.next().unwrap();
    let params = iter.map(HttpFieldParam::from).collect::<HashSet<_>>();
    Self {
      filed_name: field_name.to_string(),
      params: HttpFieldParams(params),
    }
  }
}

impl std::fmt::Display for HttpField {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut s: String = self.filed_name.clone();
    if !self.params.0.is_empty() {
      s.push(';');
      s.push_str(
        &self
          .params
          .0
          .iter()
          .map(|v| v.clone().into())
          .collect::<Vec<String>>()
          .join(";"),
      );
    }
    write!(f, "{}", s)
  }
}

/// Struct defining Http message signature parameters
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-signature-parameters
pub struct HttpSignatureParams {
  /// created unix timestamp.
  created: Option<u64>,
  /// signature expires unix timestamp.
  expires: Option<u64>,
  /// nonce
  nonce: Option<String>,
  /// algorithm name
  alg: Option<String>,
  /// key id.
  keyid: Option<String>,
  /// tag
  tag: Option<String>,
  /// ordered message components, i.e., string of http_fields and derived_components
  message_components: Vec<String>,
}

impl std::fmt::Display for HttpSignatureParams {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut s: String = format!("({})", self.message_components.join(" "));
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
    let message_components = iter
      .next()
      .unwrap()
      .split(' ')
      .map(|v| v.to_string())
      .filter(|v| !v.is_empty())
      .collect::<Vec<String>>();
    let mut params = Self {
      created: None,
      expires: None,
      nonce: None,
      alg: None,
      keyid: None,
      tag: None,
      message_components,
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

/// Configuration for Http message signature parameters
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-signature-parameters
pub struct HttpSignatureParamsBuildConfig {
  /// created unix timestamp. if none and set_created = false, use current timestamp
  created: Option<u64>,
  /// if true, `created` is set.
  set_created: bool,
  /// signature expires in `expires_in` seconds after `created`, i.e., `expires` is set to be `created + expires_in`.
  /// if none and contains_expires = true, use DEFAULT_EXPIRES_IN seconds
  expires_in: Option<u64>,
  /// if true, `expires` is set to be `created + expires_in`.
  set_expires: bool,
  /// if none and contains_nonce = true, use random nonce, i.e., artificial nonce is set if Some<String> and contains_nonce = true.
  nonce: Option<String>,
  /// if true, `nonce` is set.
  set_nonce: bool,
  /// algorithm name
  alg: Option<String>,
  /// key id.
  keyid: Option<String>,
  /// tag
  tag: Option<String>,
  /// derived components
  derived_components: HashSet<HttpDerivedComponent>,
  /// http fields like `date`, `content-type`, `content-length`, etc.
  /// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-http-fields
  http_fields: HashSet<HttpField>,
}

impl Default for HttpSignatureParamsBuildConfig {
  fn default() -> Self {
    Self {
      created: None,
      set_created: true,
      expires_in: Some(DEFAULT_EXPIRES_IN),
      set_expires: false,
      nonce: None,
      set_nonce: false,
      alg: None,
      keyid: None,
      tag: None,
      derived_components: HashSet::default(),
      http_fields: HashSet::default(),
    }
  }
}

impl HttpSignatureParamsBuildConfig {
  /// Set keyid and alg from the key
  pub fn set_key_info(&mut self, key: &impl VerifyingKey) {
    self.keyid = Some(key.key_id().to_string());
    self.alg = Some(key.alg().to_string());
  }
  /// Set derived components
  pub fn set_derived_components(&mut self, components: &[&str]) {
    self.derived_components = components.iter().map(|&c| HttpDerivedComponent::from(c)).collect();
  }
  /// Set http fields
  pub fn set_http_fields(&mut self, fields: &[&str]) {
    self.http_fields = fields.iter().map(|&f| HttpField::from(f)).collect();
  }
  /// Derive HttpSignatureParams object
  pub fn derive_http_signature_params(&self) -> HttpSignatureParams {
    let mut message_components = self
      .derived_components
      .iter()
      .map(|c| c.to_string())
      .collect::<Vec<String>>();
    message_components.extend(self.http_fields.iter().map(|f| f.to_string()).collect::<Vec<String>>());
    let created = if self.set_created {
      if self.created.is_none() {
        Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
      } else {
        self.created
      }
    } else {
      None
    };
    let expires = if self.set_expires {
      if self.expires_in.is_none() {
        Some(created.unwrap() + DEFAULT_EXPIRES_IN)
      } else {
        created.map(|v| v + self.expires_in.unwrap())
      }
    } else {
      None
    };
    let nonce = if self.set_nonce {
      if self.nonce.is_none() {
        // generate 32 bytes random nonce in base64url encoding
        let mut rng = rand::thread_rng();
        let nonce = rng.gen::<[u8; 32]>();
        Some(URL_SAFE_NO_PAD.encode(nonce))
      } else {
        self.nonce.clone()
      }
    } else {
      None
    };

    HttpSignatureParams {
      created,
      expires,
      nonce,
      alg: self.alg.clone(),
      keyid: self.keyid.clone(),
      tag: self.tag.clone(),
      message_components,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::PublicKey;
  const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
  const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##;
  const EDDSA_KEY_ID: &str = "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is";

  #[test]
  fn test_derived_components() {
    let params = HttpDerivedComponent::from("\"@method\";req");
    assert_eq!(params.component, HttpDerivedComponentInner::Method);
    assert_eq!(
      params.params.0,
      vec![HttpFieldParam::Req].into_iter().collect::<HashSet<_>>()
    );

    // drops invalid field params
    let params = HttpDerivedComponent::from("\"@path\";req;key=\"test\"");
    assert_eq!(params.component, HttpDerivedComponentInner::Path);
    assert_eq!(
      params.params.0,
      vec![HttpFieldParam::Req].into_iter().collect::<HashSet<_>>()
    );
  }

  #[test]
  fn test_http_general_field() {
    let params = HttpField::from("\"example-header\";bs");
    assert_eq!(params.filed_name, "\"example-header\"");
    assert_eq!(
      params.params.0,
      vec![HttpFieldParam::Bs].into_iter().collect::<HashSet<_>>()
    );

    // keeps field params
    let params = HttpField::from("\"example-header\";bs;key=\"test\"");
    assert_eq!(params.filed_name, "\"example-header\"");
    assert_eq!(
      params.params.0,
      vec![HttpFieldParam::Bs, HttpFieldParam::Key("test".to_string())]
        .into_iter()
        .collect::<HashSet<_>>()
    );
  }

  #[test]
  fn test_set_key_info() {
    let mut params = HttpSignatureParamsBuildConfig::default();
    params.set_derived_components(&["\"@method\"", "\"@path\";bs", "\"@authority\""]);
    assert_eq!(
      params.derived_components,
      vec!["\"@method\"", "\"@path\";bs", "\"@authority\""]
        .into_iter()
        .map(HttpDerivedComponent::from)
        .collect::<HashSet<_>>()
    );
    params.set_key_info(&PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap());
    assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
    assert_eq!(params.alg, Some("ed25519".to_string()));
  }

  #[test]
  fn test_http_signature_params() {
    let mut params = HttpSignatureParamsBuildConfig::default();
    params.set_derived_components(&["\"@method\"", "\"@path\";bs", "\"@authority\"", "\"@scheme\";req"]);
    params.set_http_fields(&["\"date\"", "\"content-type\";bs", "\"content-length\""]);
    params.set_key_info(&PublicKey::from_pem(EDDSA_PUBLIC_KEY).unwrap());

    let params = params.derive_http_signature_params();
    assert!(params.created.is_some());
    assert!(params.expires.is_none());
    assert!(params.nonce.is_none());
    assert_eq!(params.alg, Some("ed25519".to_string()));
    assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
    assert_eq!(params.tag, None);

    assert!(params.message_components.contains(&"\"@method\"".to_string()));
    // only `req` field param is allowed for derived components unlike general http fields
    // drops bs field param
    assert!(params.message_components.contains(&"\"@path\"".to_string()));
    // req remains
    assert!(params.message_components.contains(&"\"@scheme\";req".to_string()));

    assert!(params.message_components.contains(&"\"@authority\"".to_string()));
    assert!(params.message_components.contains(&"\"date\"".to_string()));
    assert!(params.message_components.contains(&"\"content-type\";bs".to_string()));
    assert!(params.message_components.contains(&"\"content-length\"".to_string()));

    println!("{}", params);
  }

  #[test]
  fn test_from_string_signature_params() {
    let value = r##"("@method" "@path" "@scheme";req "@authority" "content-type";bs "date" "content-length");created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is""##;
    let params = HttpSignatureParams::try_from(value);
    assert!(params.is_ok());
    let params = params.unwrap();
    assert_eq!(params.created, Some(1704972031));
    assert_eq!(params.expires, None);
    assert_eq!(params.nonce, None);
    assert_eq!(params.alg, Some("ed25519".to_string()));
    assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
    assert_eq!(params.tag, None);
    assert_eq!(
      params.message_components,
      vec![
        "\"@method\"",
        "\"@path\"",
        "\"@scheme\";req",
        "\"@authority\"",
        "\"content-type\";bs",
        "\"date\"",
        "\"content-length\""
      ]
      .into_iter()
      .map(|v| v.to_string())
      .collect::<Vec<String>>()
    );
  }
  #[test]
  fn test_from_string_signature_params_with_no_message_components() {
    let value = r##"();created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is""##;
    let params = HttpSignatureParams::try_from(value);
    assert!(params.is_ok());
    let params = params.unwrap();
    assert_eq!(params.created, Some(1704972031));
    assert_eq!(params.expires, None);
    assert_eq!(params.nonce, None);
    assert_eq!(params.alg, Some("ed25519".to_string()));
    assert_eq!(params.keyid, Some(EDDSA_KEY_ID.to_string()));
    assert_eq!(params.tag, None);
    assert!(params.message_components.is_empty());
  }
}
