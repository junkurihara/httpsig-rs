use rustc_hash::FxHashSet as HashSet;

/* ---------------------------------------------------------------- */
/// Http message component
pub(crate) struct HttpMessageComponent {
  /// Http message component identifier
  id: HttpMessageComponentIdentifier,
  /// Http message component value
  value: HttpMessageComponentValue,
}

impl TryFrom<&str> for HttpMessageComponent {
  type Error = anyhow::Error;
  fn try_from(val: &str) -> std::result::Result<Self, anyhow::Error> {
    let Some((id, value)) = val.split_once(':') else {
      return Err(anyhow::anyhow!("Invalid http message component: {}", val));
    };
    Ok(Self {
      id: HttpMessageComponentIdentifier::from(id.trim()),
      value: HttpMessageComponentValue::from(value.trim()),
    })
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
/// Http message component value
pub(crate) struct HttpMessageComponentValue {
  /// inner value originally from http message header or derived from http message
  inner: String,
}

impl From<&str> for HttpMessageComponentValue {
  fn from(val: &str) -> Self {
    Self { inner: val.to_string() }
  }
}

impl std::fmt::Display for HttpMessageComponentValue {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.inner)
  }
}

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Hash, Debug)]
/// Http message component identifier
pub(crate) enum HttpMessageComponentIdentifier {
  /// Http field component
  HttpField(HttpFieldComponentId),
  /// Derived commponent
  Derived(DerivedComponentId),
}

impl From<&str> for HttpMessageComponentIdentifier {
  fn from(val: &str) -> Self {
    if val.starts_with("\"@") {
      Self::Derived(DerivedComponentId::from(val))
    } else {
      Self::HttpField(HttpFieldComponentId::from(val))
    }
  }
}

impl std::fmt::Display for HttpMessageComponentIdentifier {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::HttpField(val) => write!(f, "{}", val),
      Self::Derived(val) => write!(f, "{}", val),
    }
  }
}

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
/// Http message component parameters that appends with `;` in the signature input
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#secion-2.1
pub(crate) enum HttpMessageComponentParam {
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

impl From<HttpMessageComponentParam> for String {
  fn from(val: HttpMessageComponentParam) -> Self {
    match val {
      HttpMessageComponentParam::Sf => "sf".to_string(),
      HttpMessageComponentParam::Key(val) => format!("key=\"{}\"", val),
      HttpMessageComponentParam::Bs => "bs".to_string(),
      HttpMessageComponentParam::Tr => "tr".to_string(),
      HttpMessageComponentParam::Req => "req".to_string(),
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
        } else {
          panic!("Invalid http field param: {}", val)
        }
      }
    }
  }
}

#[derive(PartialEq, Eq, Debug)]
pub(crate) struct HttpMessageComponentParams(pub(crate) HashSet<HttpMessageComponentParam>);
impl std::hash::Hash for HttpMessageComponentParams {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    let mut params = self.0.iter().map(|v| v.clone().into()).collect::<Vec<String>>();
    params.sort();
    params.hash(state);
  }
}

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
/// Derive components from http message, which is expressed as @method, @path, @authority, etc. in @signature-params
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-derived-components
pub(crate) enum DerivedComponentName {
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
impl AsRef<str> for DerivedComponentName {
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
impl From<DerivedComponentName> for String {
  fn from(val: DerivedComponentName) -> Self {
    val.as_ref().to_string()
  }
}
impl From<&str> for DerivedComponentName {
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
pub(crate) struct DerivedComponentId {
  /// derived component
  pub(crate) component_name: DerivedComponentName,
  /// parameters
  pub(crate) params: HttpMessageComponentParams,
}

impl From<&str> for DerivedComponentId {
  /// this feeds `"<derived-component>";<field-params>` format, e.g., `"@method";req`
  fn from(val: &str) -> Self {
    let mut iter = val.split(';');
    let component = iter.next().unwrap();
    // only `req` field param is allowed for derived components unlike general http fields
    let params = iter
      .map(HttpMessageComponentParam::from)
      .filter(|v| matches!(v, HttpMessageComponentParam::Req))
      .collect::<HashSet<_>>();
    Self {
      component_name: DerivedComponentName::from(component),
      params: HttpMessageComponentParams(params),
    }
  }
}
impl std::fmt::Display for DerivedComponentId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut s: String = self.component_name.clone().into();
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

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Hash, Debug)]
/// Http field component setting with optional parameters
/// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-http-fields
pub(crate) struct HttpFieldComponentId {
  /// field name
  pub(crate) filed_name: String,
  /// parameters
  pub(crate) params: HttpMessageComponentParams,
}

impl From<&str> for HttpFieldComponentId {
  /// this feeds `"<field-name>";<field-params>` format, e.g., `"example-header";bs`
  fn from(val: &str) -> Self {
    let mut iter = val.split(';');
    let field_name = iter.next().unwrap();
    let params = iter.map(HttpMessageComponentParam::from).collect::<HashSet<_>>();
    Self {
      filed_name: field_name.to_string(),
      params: HttpMessageComponentParams(params),
    }
  }
}

impl std::fmt::Display for HttpFieldComponentId {
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

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_http_message_component() {
    let comp = HttpMessageComponent::try_from("\"example-header\";bs: example-value").unwrap();
    assert_eq!(
      comp.id,
      HttpMessageComponentIdentifier::HttpField(HttpFieldComponentId {
        filed_name: "\"example-header\"".to_string(),
        params: HttpMessageComponentParams(vec![HttpMessageComponentParam::Bs].into_iter().collect::<HashSet<_>>())
      })
    );
    assert_eq!(comp.value.inner, "example-value");
    assert_eq!(comp.to_string(), "\"example-header\";bs: example-value");

    let comp = HttpMessageComponent::try_from("\"@method\";req: POST").unwrap();
    assert_eq!(
      comp.id,
      HttpMessageComponentIdentifier::Derived(DerivedComponentId {
        component_name: DerivedComponentName::Method,
        params: HttpMessageComponentParams(vec![HttpMessageComponentParam::Req].into_iter().collect::<HashSet<_>>())
      })
    );
    assert_eq!(comp.value.inner, "POST");
    assert_eq!(comp.to_string(), "\"@method\";req: POST");

    let comp = HttpMessageComponent::try_from("\"x-empty-header\": ").unwrap();
    assert_eq!(
      comp.id,
      HttpMessageComponentIdentifier::HttpField(HttpFieldComponentId {
        filed_name: "\"x-empty-header\"".to_string(),
        params: HttpMessageComponentParams(HashSet::default())
      })
    );
    assert_eq!(comp.value.inner, "");
    assert_eq!(comp.to_string(), "\"x-empty-header\": ");
  }
  #[test]
  fn test_http_message_component_value() {
    let val = HttpMessageComponentValue::from("example-value");
    assert_eq!(val.inner, "example-value");
    assert_eq!(val.to_string(), "example-value");

    let val = HttpMessageComponentValue::from("");
    assert_eq!(val.inner, "");
    assert_eq!(val.to_string(), "");
  }
  #[test]
  fn test_http_message_component_id_enum() {
    let params = HttpMessageComponentIdentifier::from("\"example-header\";bs");
    assert_eq!(
      params,
      HttpMessageComponentIdentifier::HttpField(HttpFieldComponentId {
        filed_name: "\"example-header\"".to_string(),
        params: HttpMessageComponentParams(vec![HttpMessageComponentParam::Bs].into_iter().collect::<HashSet<_>>())
      })
    );

    let params = HttpMessageComponentIdentifier::from("\"@method\";req");
    assert_eq!(
      params,
      HttpMessageComponentIdentifier::Derived(DerivedComponentId {
        component_name: DerivedComponentName::Method,
        params: HttpMessageComponentParams(vec![HttpMessageComponentParam::Req].into_iter().collect::<HashSet<_>>())
      })
    );
  }
  #[test]
  fn test_derived_components() {
    let params = DerivedComponentId::from("\"@method\";req");
    assert_eq!(params.component_name, DerivedComponentName::Method);
    assert_eq!(
      params.params.0,
      vec![HttpMessageComponentParam::Req].into_iter().collect::<HashSet<_>>()
    );

    // drops invalid field params
    let params = DerivedComponentId::from("\"@path\";req;key=\"test\"");
    assert_eq!(params.component_name, DerivedComponentName::Path);
    assert_eq!(
      params.params.0,
      vec![HttpMessageComponentParam::Req].into_iter().collect::<HashSet<_>>()
    );
  }

  #[test]
  fn test_http_general_field() {
    let params = HttpFieldComponentId::from("\"example-header\";bs");
    assert_eq!(params.filed_name, "\"example-header\"");
    assert_eq!(
      params.params.0,
      vec![HttpMessageComponentParam::Bs].into_iter().collect::<HashSet<_>>()
    );

    // keeps field params
    let params = HttpFieldComponentId::from("\"example-header\";bs;key=\"test\"");
    assert_eq!(params.filed_name, "\"example-header\"");
    assert_eq!(
      params.params.0,
      vec![
        HttpMessageComponentParam::Bs,
        HttpMessageComponentParam::Key("test".to_string())
      ]
      .into_iter()
      .collect::<HashSet<_>>()
    );
  }
}
