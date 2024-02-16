use super::{
  component_id::HttpMessageComponentId,
  component_name::{DerivedComponentName, HttpMessageComponentName},
  component_param::{handle_params_key_into, handle_params_sf, HttpMessageComponentParam},
  component_value::HttpMessageComponentValue,
};
use crate::{
  error::{HttpSigError, HttpSigResult},
  trace::*,
};

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
  type Error = HttpSigError;
  /// Create HttpMessageComponent from serialized string, i.e., `"<id>": <value>` of lines in the signature base of HTTP header.
  /// We suppose that the value was correctly serialized as a line of signature base.
  fn try_from(val: &str) -> Result<Self, Self::Error> {
    let Some((id, value)) = val.split_once(':') else {
      return Err(HttpSigError::InvalidComponent(format!(
        "Invalid http message component: {val}"
      )));
    };
    let id = id.trim();

    // check if id is wrapped by double quotations
    if !(id.starts_with('"') && (id.ends_with('"') || id[1..].contains("\";"))) {
      return Err(HttpSigError::InvalidComponentId(format!(
        "Invalid http message component id: {id}"
      )));
    }

    Ok(Self {
      id: HttpMessageComponentId::try_from(id)?,
      value: HttpMessageComponentValue::from(value.trim()),
    })
  }
}

impl TryFrom<(&HttpMessageComponentId, &[String])> for HttpMessageComponent {
  type Error = HttpSigError;

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
/// Build derived component from given id and its associated field values
pub(super) fn build_derived_component(
  id: &HttpMessageComponentId,
  field_values: &[String],
) -> HttpSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::Derived(derived_id) = &id.name else {
    return Err(HttpSigError::InvalidComponent(
      "invalid http message component name as derived component".to_string(),
    ));
  };
  if field_values.is_empty() {
    return Err(HttpSigError::InvalidComponent(
      "derived component requires field values".to_string(),
    ));
  }
  // ensure only `req` and `name` are allowed for derived component parameters
  if !id
    .params
    .0
    .iter()
    .all(|p| matches!(p, HttpMessageComponentParam::Req | HttpMessageComponentParam::Name(_)))
  {
    return Err(HttpSigError::InvalidComponent(
      "invalid parameter for derived component".to_string(),
    ));
  }

  let value = match derived_id {
    DerivedComponentName::Method => HttpMessageComponentValue::from(field_values[0].to_ascii_uppercase().as_ref()),
    DerivedComponentName::TargetUri => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    DerivedComponentName::Authority => HttpMessageComponentValue::from(field_values[0].to_ascii_lowercase().as_ref()),
    DerivedComponentName::Scheme => HttpMessageComponentValue::from(field_values[0].to_ascii_lowercase().as_ref()),
    DerivedComponentName::RequestTarget => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    DerivedComponentName::Path => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    DerivedComponentName::Query => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    DerivedComponentName::Status => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    DerivedComponentName::QueryParam => {
      let name = id.params.0.iter().find_map(|p| match p {
        HttpMessageComponentParam::Name(name) => Some(name),
        _ => None,
      });
      if name.is_none() {
        return Err(HttpSigError::InvalidComponent(
          "query-param derived component requires name parameter".to_string(),
        ));
      };
      let name = name.unwrap();
      let kvs = field_values
        .iter()
        .filter(|v| v.contains('='))
        .map(|v| v.split_once('=').unwrap())
        .filter(|(k, _)| *k == name.as_str())
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
      HttpMessageComponentValue::from(kvs.join(", ").as_ref())
    }
    DerivedComponentName::SignatureParams => {
      let value = field_values[0].to_string();
      let opt_pair = value.trim().split_once('=');
      if opt_pair.is_none() {
        return Err(HttpSigError::InvalidComponent(
          "invalid signature-params derived component".to_string(),
        ));
      }
      let (key, value) = opt_pair.unwrap();
      HttpMessageComponentValue::from((key, value))
    }
  };
  let component = HttpMessageComponent { id: id.clone(), value };
  Ok(component)
}

/* ---------------------------------------------------------------- */
/// Build http field component from given id and its associated field values
/// NOTE: field_value must be ones of request for `req` param
pub(super) fn build_http_field_component(
  id: &HttpMessageComponentId,
  field_values: &[String],
) -> HttpSigResult<HttpMessageComponent> {
  let mut field_values = field_values.to_vec();
  let params = &id.params;

  for p in params.0.iter() {
    match p {
      HttpMessageComponentParam::Sf => {
        handle_params_sf(&mut field_values)?;
      }
      HttpMessageComponentParam::Key(key) => {
        field_values = handle_params_key_into(&field_values, key)?;
      }
      HttpMessageComponentParam::Bs => {
        return Err(HttpSigError::NotYetImplemented("`bs` is not supported yet".to_string()));
      }
      HttpMessageComponentParam::Req => {
        debug!("`req` is given for http field component");
      }
      HttpMessageComponentParam::Tr => return Err(HttpSigError::NotYetImplemented("`tr` is not supported yet".to_string())),
      HttpMessageComponentParam::Name(_) => {
        return Err(HttpSigError::NotYetImplemented(
          "`name` is only for derived component query-params".to_string(),
        ));
      }
    }
  }

  // TODO: case: some values contains ','

  let field_values_str = field_values.join(", ");

  let component = HttpMessageComponent {
    id: id.clone(),
    value: HttpMessageComponentValue::from(field_values_str.as_ref()),
  };
  Ok(component)
}

/* ---------------------------------------------------------------- */
#[cfg(test)]
mod tests {
  use super::*;
  type IndexSet<K> = indexmap::IndexSet<K, fxhash::FxBuildHasher>;

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
        assert_eq!(comp.id.params.0, IndexSet::default());
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
        assert_eq!(comp.id.params.0, IndexSet::default());
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
        .collect::<IndexSet<_>>()
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
        .collect::<IndexSet<_>>()
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

  #[test]
  fn test_build_http_field_component() {
    let id = HttpMessageComponentId::try_from("content-type").unwrap();
    let field_values = vec!["application/json".to_owned()];
    let component = build_http_field_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(component.value, HttpMessageComponentValue::from("application/json"));
    assert_eq!(component.to_string(), "\"content-type\": application/json");
  }
  #[test]
  fn test_build_http_field_component_multiple_values() {
    let id = HttpMessageComponentId::try_from("\"content-type\"").unwrap();
    let field_values = vec!["application/json".to_owned(), "application/json-patch+json".to_owned()];
    let component = build_http_field_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(
      component.value,
      HttpMessageComponentValue::from("application/json, application/json-patch+json")
    );
    assert_eq!(
      component.to_string(),
      "\"content-type\": application/json, application/json-patch+json"
    );
  }
  #[test]
  fn test_build_http_field_component_sf() {
    let id = HttpMessageComponentId::try_from("\"content-type\";sf").unwrap();
    let field_values = vec![
      "application/json; patched=true".to_owned(),
      "application/json-patch+json;patched".to_owned(),
    ];
    let component = build_http_field_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(
      component.value,
      HttpMessageComponentValue::from("application/json;patched=true, application/json-patch+json;patched")
    );
    assert_eq!(
      component.to_string(),
      "\"content-type\";sf: application/json;patched=true, application/json-patch+json;patched"
    );
  }
  #[test]
  fn test_build_http_field_component_key() {
    let id = HttpMessageComponentId::try_from("\"example-header\";key=\"patched\"").unwrap();
    let field_values = vec!["patched=12345678".to_owned()];
    let component = build_http_field_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(component.value, HttpMessageComponentValue::from("12345678"));
    assert_eq!(component.to_string(), "\"example-header\";key=\"patched\": 12345678");
  }
  #[test]
  fn test_build_http_field_component_key_multiple_values() {
    let id = HttpMessageComponentId::try_from("\"example-header\";key=\"patched\"").unwrap();
    let field_values = vec![
      "patched=12345678".to_owned(),
      "patched=87654321".to_owned(),
      "not-patched=12345678".to_owned(),
    ];
    let component = build_http_field_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(component.value, HttpMessageComponentValue::from("12345678, 87654321"));
    assert_eq!(
      component.to_string(),
      "\"example-header\";key=\"patched\": 12345678, 87654321"
    );
  }

  #[test]
  fn test_build_derived_component() {
    let id = HttpMessageComponentId::try_from("@method").unwrap();
    let field_values = vec!["GET".to_owned()];
    let component = build_derived_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(component.value, HttpMessageComponentValue::from("GET"));
    assert_eq!(component.to_string(), "\"@method\": GET");

    let id = HttpMessageComponentId::try_from("@target-uri").unwrap();
    let field_values = vec!["https://example.com/foo".to_owned()];
    let component = build_derived_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(component.value, HttpMessageComponentValue::from("https://example.com/foo"));
    assert_eq!(component.to_string(), "\"@target-uri\": https://example.com/foo");
  }
  #[test]
  fn test_build_http_field_component_query_param() {
    let id = HttpMessageComponentId::try_from("\"@query-param\";name=\"var\"").unwrap();
    let query_param = "var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&ok";
    let field_values = query_param.split('&').map(|v| v.to_owned()).collect::<Vec<_>>();
    let component = build_derived_component(&id, &field_values).unwrap();
    assert_eq!(component.id, id);
    assert_eq!(
      component.value,
      HttpMessageComponentValue::from("this%20is%20a%20big%0Amultiline%20value")
    );
    assert_eq!(
      component.to_string(),
      "\"@query-param\";name=\"var\": this%20is%20a%20big%0Amultiline%20value"
    );
  }

  #[test]
  fn test_disallow_invalid_params() {
    let id = HttpMessageComponentId::try_from("\"@method\";key=\"patched\"");
    assert!(id.is_err());
  }
}
