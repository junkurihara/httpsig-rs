use super::{
  component_name::{DerivedComponentName, HttpMessageComponentName},
  component_param::{HttpMessageComponentParam, HttpMessageComponentParams},
};
use anyhow::{bail, ensure};

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
