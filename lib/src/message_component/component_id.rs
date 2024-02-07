use super::{
  component_name::{DerivedComponentName, HttpMessageComponentName},
  component_param::{HttpMessageComponentParam, HttpMessageComponentParams},
};
use anyhow::ensure;
use sfv::Parser;

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
  /// Parse http message component id from string
  /// Accept `"<name>";<params>` or `"<name>"` (with double quotations).
  /// But accept string in the form of `<name>` (without double quotations) when no param is given
  fn try_from(val: &str) -> std::result::Result<Self, Self::Error> {
    let val = val.trim();
    let item = if !val.starts_with('"') && !val.ends_with('"') && !val.is_empty() && !val.contains('"') {
      // maybe insufficient, but it's enough for now
      Parser::parse_item(format!("\"{val}\"").as_bytes()).map_err(|e| anyhow::anyhow!(e))?
    } else {
      Parser::parse_item(val.as_bytes()).map_err(|e| anyhow::anyhow!(e))?
    };

    let res = Self {
      name: HttpMessageComponentName::try_from(&item.bare_item)?,
      params: HttpMessageComponentParams::try_from(&item.params)?,
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
