use rustc_hash::FxHashSet as HashSet;

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
/// Http message component parameters
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
