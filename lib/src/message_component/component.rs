use super::parse::{build_derived_component, build_http_field_component};
use anyhow::{bail, ensure};
use rustc_hash::FxHashSet as HashSet;

/* ---------------------------------------------------------------- */
#[derive(Debug, Clone)]
/// Http message component
pub struct HttpMessageComponent {
  /// Http message component id
  pub id: HttpMessageComponentId,
  /// Http message component value
  pub value: HttpMessageComponentValue,
}

impl TryFrom<&str> for HttpMessageComponent {
  type Error = anyhow::Error;
  /// Create HttpMessageComponent from serialized string, i.e., `"<id>": <value>` of lines in the signature base of HTTP header.
  /// We suppose that the value was correctly serialized as a line of signature base.
  fn try_from(val: &str) -> Result<Self, Self::Error> {
    let Some((id, value)) = val.split_once(':') else {
      bail!("Invalid http message component: {}", val);
    };
    let id = id.trim();

    // check if id is wrapped by double quotations
    ensure!(
      id.starts_with('"') && (id.ends_with('"') || id[1..].contains("\";")),
      "Invalid http message component id: {}",
      id
    );

    Ok(Self {
      id: HttpMessageComponentId::try_from(id)?,
      value: HttpMessageComponentValue::from(value.trim()),
    })
  }
}

impl TryFrom<(&HttpMessageComponentId, &[String])> for HttpMessageComponent {
  type Error = anyhow::Error;

  /// Build http message component from given id and its associated field values
  fn try_from((id, field_values): (&HttpMessageComponentId, &[String])) -> Result<Self, Self::Error> {
    match &id.name {
      HttpMessageComponentName::HttpField(_) => build_http_field_component(id, field_values),
      HttpMessageComponentName::Derived(_) => build_derived_component(id, field_values),
    }
  }
}

impl std::fmt::Display for HttpMessageComponent {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // This always can append single trailing space (SP) for empty value
    // https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#section-2.1
    write!(f, "{}: {}", self.id, self.value)
  }
}

/* ---------------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Http message component id
pub struct HttpMessageComponentId {
  /// Http message component name
  pub name: HttpMessageComponentName,
  /// Http message component params
  pub params: HttpMessageComponentParams,
}

impl HttpMessageComponentId {
  /// Add `req` field param to the component, which is used to generate signature input for response from its corresponding request.
  pub fn add_req_param(&mut self) {
    self.params.0.insert(HttpMessageComponentParam::Req);
  }
}

impl std::fmt::Display for HttpMessageComponentId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}{}", self.name, self.params)
  }
}

impl TryFrom<&str> for HttpMessageComponentId {
  type Error = anyhow::Error;
  fn try_from(val: &str) -> std::result::Result<Self, Self::Error> {
    let (name, params) = if val.contains(';') {
      val.split_once(';').unwrap()
    } else {
      (val, "")
    };
    Self::try_from((name, params))
  }
}

impl TryFrom<(&str, &str)> for HttpMessageComponentId {
  type Error = anyhow::Error;
  fn try_from((name, params): (&str, &str)) -> std::result::Result<Self, Self::Error> {
    let name = name.trim();
    let inner_name = if name.starts_with('"') && name.ends_with('"') {
      name[1..name.len() - 1].to_string()
    } else if !name.starts_with('"') && !name.ends_with('"') {
      name.to_string()
    } else {
      bail!("Invalid http message component name: {}", name);
    };

    let res = Self {
      name: HttpMessageComponentName::from(inner_name.as_ref()),
      params: HttpMessageComponentParams::from(params),
    };

    // assert for query param
    if res.params.0.iter().any(|v| matches!(v, &HttpMessageComponentParam::Name(_))) {
      ensure!(
        matches!(res.name, HttpMessageComponentName::Derived(DerivedComponentName::QueryParam)),
        "Invalid http message component id: {}",
        res
      );
    }

    // assert for http field components
    // only req field param is allowed
    if res.params.0.iter().any(|v| {
      matches!(v, &HttpMessageComponentParam::Bs)
        || matches!(v, &HttpMessageComponentParam::Sf)
        || matches!(v, &HttpMessageComponentParam::Tr)
        || matches!(v, &HttpMessageComponentParam::Key(_))
    }) {
      ensure!(
        matches!(res.name, HttpMessageComponentName::HttpField(_)),
        "Invalid http message component id: {}",
        res
      );
    }

    Ok(res)
  }
}

/* ---------------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq)]
/// Http message component value
pub struct HttpMessageComponentValue {
  /// inner value originally from http message header or derived from http message
  inner: HttpMessageComponentValueInner,
}

impl From<&str> for HttpMessageComponentValue {
  fn from(val: &str) -> Self {
    Self {
      inner: HttpMessageComponentValueInner::String(val.to_string()),
    }
  }
}

impl From<(&str, &str)> for HttpMessageComponentValue {
  fn from((key, val): (&str, &str)) -> Self {
    Self {
      inner: HttpMessageComponentValueInner::KeyValue((key.to_string(), val.to_string())),
    }
  }
}

impl std::fmt::Display for HttpMessageComponentValue {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.inner)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Http message component value inner, simple string or key-value pair
enum HttpMessageComponentValueInner {
  String(String),
  KeyValue((String, String)),
}

impl std::fmt::Display for HttpMessageComponentValueInner {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::String(val) => write!(f, "{}", val),
      Self::KeyValue((_, val)) => write!(f, "{}", val),
    }
  }
}

impl HttpMessageComponentValue {
  /// Get key if pair, otherwise None
  pub fn key(&self) -> Option<&str> {
    match &self.inner {
      HttpMessageComponentValueInner::String(_) => None,
      HttpMessageComponentValueInner::KeyValue((key, _)) => Some(key.as_ref()),
    }
  }
  /// Get key value connected with `=`, or just value
  pub fn as_field_value(&self) -> String {
    match &self.inner {
      HttpMessageComponentValueInner::String(val) => val.to_owned(),
      HttpMessageComponentValueInner::KeyValue((key, val)) => format!("{}={}", key, val),
    }
  }
  /// Get value only
  pub fn as_component_value(&self) -> &str {
    match &self.inner {
      HttpMessageComponentValueInner::String(val) => val.as_ref(),
      HttpMessageComponentValueInner::KeyValue((_, val)) => val.as_ref(),
    }
  }
}

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
/// Http message component identifier
pub enum HttpMessageComponentName {
  /// Http field component, which is in the form of `<field_name>` without being wrapped by double quotations
  HttpField(String),
  /// Derived component
  Derived(DerivedComponentName),
}

impl From<&str> for HttpMessageComponentName {
  fn from(val: &str) -> Self {
    if val.starts_with('@') {
      Self::Derived(DerivedComponentName::from(val))
    } else {
      Self::HttpField(val.to_string())
    }
  }
}

impl std::fmt::Display for HttpMessageComponentName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::HttpField(val) => write!(f, "\"{}\"", val),
      Self::Derived(val) => write!(f, "\"{}\"", val),
    }
  }
}

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
/// Http message component parameters that appends with `;` in the signature input
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#secion-2.1
pub enum HttpMessageComponentParam {
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
  // name: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-query-parameters
  /// This will be encoded to `;name="..."` in the signature input
  Name(String),
}

impl From<HttpMessageComponentParam> for String {
  fn from(val: HttpMessageComponentParam) -> Self {
    match val {
      HttpMessageComponentParam::Sf => "sf".to_string(),
      HttpMessageComponentParam::Key(val) => format!("key=\"{val}\""),
      HttpMessageComponentParam::Bs => "bs".to_string(),
      HttpMessageComponentParam::Tr => "tr".to_string(),
      HttpMessageComponentParam::Req => "req".to_string(),
      HttpMessageComponentParam::Name(v) => format!("name=\"{v}\""),
    }
  }
}
impl From<&str> for HttpMessageComponentParam {
  fn from(val: &str) -> Self {
    match val {
      "sf" => Self::Sf,
      "bs" => Self::Bs,
      "tr" => Self::Tr,
      "req" => Self::Req,
      _ => {
        if val.starts_with("key=\"") && val.ends_with('"') {
          Self::Key(val[5..val.len() - 1].to_string())
        } else if val.starts_with("name=\"") && val.ends_with('"') {
          Self::Name(val[6..val.len() - 1].to_string())
        } else {
          panic!("Invalid http field param: {}", val)
        }
      }
    }
  }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct HttpMessageComponentParams(pub HashSet<HttpMessageComponentParam>);
impl std::hash::Hash for HttpMessageComponentParams {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    let mut params = self.0.iter().map(|v| v.clone().into()).collect::<Vec<String>>();
    params.sort();
    params.hash(state);
  }
}
impl From<&str> for HttpMessageComponentParams {
  fn from(val: &str) -> Self {
    let mut hs = HashSet::default();
    val.split(';').for_each(|v| {
      if !v.is_empty() {
        let param = HttpMessageComponentParam::from(v);
        hs.insert(param);
      }
    });
    Self(hs)
  }
}
impl std::fmt::Display for HttpMessageComponentParams {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if !self.0.is_empty() {
      write!(
        f,
        ";{}",
        self.0.iter().map(|v| v.clone().into()).collect::<Vec<String>>().join(";")
      )
    } else {
      Ok(())
    }
  }
}

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
/// Derive components from http message, which is expressed as @method, @path, @authority, etc. in @signature-params
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-derived-components
pub enum DerivedComponentName {
  Method,
  TargetUri,
  Authority,
  Scheme,
  RequestTarget,
  Path,
  Query,
  QueryParam,
  Status,
  SignatureParams,
}
impl AsRef<str> for DerivedComponentName {
  fn as_ref(&self) -> &str {
    match self {
      Self::Method => "@method",
      Self::TargetUri => "@target-uri",
      Self::Authority => "@authority",
      Self::Scheme => "@scheme",
      Self::RequestTarget => "@request-target",
      Self::Path => "@path",
      Self::Query => "@query",
      Self::QueryParam => "@query-param",
      Self::Status => "@status",
      Self::SignatureParams => "@signature-params",
    }
  }
}
impl From<DerivedComponentName> for String {
  fn from(val: DerivedComponentName) -> Self {
    val.as_ref().to_string()
  }
}
impl From<&str> for DerivedComponentName {
  fn from(val: &str) -> Self {
    match val {
      "@method" => Self::Method,
      "@target-uri" => Self::TargetUri,
      "@authority" => Self::Authority,
      "@scheme" => Self::Scheme,
      "@request-target" => Self::RequestTarget,
      "@path" => Self::Path,
      "@query" => Self::Query,
      "@query-param" => Self::QueryParam,
      "@status" => Self::Status,
      "@signature-params" => Self::SignatureParams,
      _ => panic!("Invalid derived component: {}", val),
    }
  }
}

impl std::fmt::Display for DerivedComponentName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", AsRef::<str>::as_ref(self))
  }
}

/* ---------------------------------------------------------------- */
#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_from_serialized_string_derived() {
    let tuples = vec![
      ("\"@method\"", "POST", DerivedComponentName::Method),
      ("\"@target-uri\"", "https://example.com/", DerivedComponentName::TargetUri),
      ("\"@authority\"", "example.com", DerivedComponentName::Authority),
      ("\"@scheme\"", "https", DerivedComponentName::Scheme),
      ("\"@request-target\"", "/path?query", DerivedComponentName::RequestTarget),
      ("\"@path\"", "/path", DerivedComponentName::Path),
      ("\"@query\"", "query", DerivedComponentName::Query),
      ("\"@query-param\";name=\"key\"", "\"value\"", DerivedComponentName::QueryParam),
      ("\"@status\"", "200", DerivedComponentName::Status),
    ];
    for (id, value, name) in tuples {
      let comp = HttpMessageComponent::try_from(format!("{}: {}", id, value).as_ref()).unwrap();
      assert_eq!(comp.id.name, HttpMessageComponentName::Derived(name));
      if !id.contains(';') {
        assert_eq!(comp.id.params.0, HashSet::default());
      } else {
        assert!(!comp.id.params.0.is_empty());
      }
      assert_eq!(comp.value.inner.to_string(), value);
      assert_eq!(comp.value.as_field_value(), value);
      assert_eq!(comp.value.key(), None);
      assert_eq!(comp.to_string(), format!("{}: {}", id, value));
    }
  }

  #[test]
  fn test_from_serialized_string_derived_query_params() {
    let (id, value, name) = ("\"@query-param\";name=\"key\"", "\"value\"", DerivedComponentName::QueryParam);
    let comp = HttpMessageComponent::try_from(format!("{}: {}", id, value).as_ref()).unwrap();
    assert_eq!(comp.id.name, HttpMessageComponentName::Derived(name));
    assert_eq!(
      comp.id.params.0.get(&HttpMessageComponentParam::Name("key".to_string())),
      Some(&HttpMessageComponentParam::Name("key".to_string()))
    );
    assert_eq!(comp.value.inner.to_string(), value);
    assert_eq!(comp.value.as_field_value(), value);
    assert_eq!(comp.value.key(), None);
    assert_eq!(comp.to_string(), format!("{}: {}", id, value));
  }

  #[test]
  fn test_from_serialized_string_http_field() {
    let tuples = vec![
      ("\"example-header\"", "example-value", "example-header"),
      ("\"example-header\";bs;tr", "example-value", "example-header"),
      ("\"example-header\";bs", "example-value", "example-header"),
      ("\"x-empty-header\"", "", "x-empty-header"),
    ];
    for (id, value, inner_name) in tuples {
      let comp = HttpMessageComponent::try_from(format!("{}: {}", id, value).as_ref()).unwrap();
      assert_eq!(comp.id.name, HttpMessageComponentName::HttpField(inner_name.to_string()));
      if !id.contains(';') {
        assert_eq!(comp.id.params.0, HashSet::default());
      } else {
        assert!(!comp.id.params.0.is_empty());
      }
      assert_eq!(comp.value.inner.to_string(), value);
      assert_eq!(comp.to_string(), format!("{}: {}", id, value));
    }
  }

  #[test]
  fn test_from_serialized_string_http_field_params() {
    let comp = HttpMessageComponent::try_from("\"example-header\";bs;tr: example-value").unwrap();
    assert_eq!(
      comp.id.name,
      HttpMessageComponentName::HttpField("example-header".to_string())
    );
    assert_eq!(
      comp.id.params.0,
      vec![HttpMessageComponentParam::Bs, HttpMessageComponentParam::Tr]
        .into_iter()
        .collect::<HashSet<_>>()
    );
  }

  #[test]
  fn test_from_serialized_string_http_field_params_key() {
    let comp = HttpMessageComponent::try_from("\"example-header\";key=\"hoge\": example-value").unwrap();
    assert_eq!(
      comp.id.name,
      HttpMessageComponentName::HttpField("example-header".to_string())
    );
    assert_eq!(
      comp.id.params.0,
      vec![HttpMessageComponentParam::Key("hoge".to_string())]
        .into_iter()
        .collect::<HashSet<_>>()
    );
  }

  #[test]
  fn test_field_params_derived_component() {
    // params check
    // only req field param is allowed
    let comp = HttpMessageComponent::try_from("\"@method\";req: POST");
    assert!(comp.is_ok());
    let comp = HttpMessageComponent::try_from("\"@method\";bs: POST");
    assert!(comp.is_err());
    let comp = HttpMessageComponent::try_from("\"@method\";key=\"hoge\": POST");
    assert!(comp.is_err());
  }
}
