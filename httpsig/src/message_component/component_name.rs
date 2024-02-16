use crate::error::{HttpSigError, HttpSigResult};
use sfv::BareItem;

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
/// Http message component identifier
pub enum HttpMessageComponentName {
  /// Http field component, which is in the form of `<field_name>` without being wrapped by double quotations
  HttpField(String),
  /// Derived component
  Derived(DerivedComponentName),
}

impl TryFrom<&BareItem> for HttpMessageComponentName {
  type Error = HttpSigError;
  fn try_from(value: &BareItem) -> HttpSigResult<Self> {
    match value {
      BareItem::String(name) => {
        if name.starts_with('@') {
          Ok(Self::Derived(DerivedComponentName::from(name.as_str())))
        } else {
          Ok(Self::HttpField(name.to_string()))
        }
      }
      _ => Err(HttpSigError::InvalidComponentName(format!(
        "Invalid http message component name: {value:?}"
      ))),
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
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
/// Derive components from http message, which is expressed as @method, @path, @authority, etc. in @signature-params
/// https://datatracker.ietf.org/doc/html/rfc9421#name-derived-components
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
