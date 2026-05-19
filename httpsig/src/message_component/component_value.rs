use std::borrow::Cow;

/* ---------------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq)]
/// Http message component value
pub struct HttpMessageComponentValue {
  /// inner value originally from http message header or derived from http message
  inner: HttpMessageComponentValueInner,
}

impl From<String> for HttpMessageComponentValue {
  fn from(val: String) -> Self {
    Self {
      inner: HttpMessageComponentValueInner::String(val),
    }
  }
}

impl From<(String, String)> for HttpMessageComponentValue {
  fn from((key, val): (String, String)) -> Self {
    Self {
      inner: HttpMessageComponentValueInner::KeyValue((key, val)),
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
  /// Simple string value
  String(String),
  /// Key value pair, typically used for the value like `sig1=:xxxxx:` of signature-input
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
  pub fn to_field_value(&self) -> Cow<'_, str> {
    match &self.inner {
      HttpMessageComponentValueInner::String(val) => val.into(),
      HttpMessageComponentValueInner::KeyValue((key, val)) => format!("{}={}", key, val).into(),
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
