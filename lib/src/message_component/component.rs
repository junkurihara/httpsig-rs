use super::parse::{build_derived_component, build_http_field_component};
use super::{
  component_id::HttpMessageComponentId, component_name::HttpMessageComponentName, component_value::HttpMessageComponentValue,
};
use anyhow::{bail, ensure};

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
#[cfg(test)]
mod tests {
  use super::super::*;
  use super::*;

  use rustc_hash::FxHashSet as HashSet;
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
      assert_eq!(comp.value.as_field_value(), value);
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
