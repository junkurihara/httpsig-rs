use super::{
  HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName, HttpMessageComponentParam, HttpMessageComponentValue,
};
use crate::trace::*;
use anyhow::{bail, ensure};
use sfv::{Parser, SerializeValue};


/// Build derived component from given id and its associated field values
pub(super) fn build_derived_component(id: &HttpMessageComponentId, field_values: &[String]) -> anyhow::Result<HttpMessageComponent> {
  let HttpMessageComponentName::Derived(derived_id) = &id.name else {
    bail!("invalid http message component name as derived component");
  };
  ensure!(!field_values.is_empty(), "derived component requires field values");
  // ensure only `req` and `name` are allowed for derived component parameters
  ensure!(
    id.params
      .0
      .iter()
      .all(|p| matches!(p, HttpMessageComponentParam::Req | HttpMessageComponentParam::Name(_))),
    "invalid parameter for derived component"
  );

  let value = match derived_id {
    super::DerivedComponentName::Method => HttpMessageComponentValue::from(field_values[0].to_ascii_uppercase().as_ref()),
    super::DerivedComponentName::TargetUri => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    super::DerivedComponentName::Authority => HttpMessageComponentValue::from(field_values[0].to_ascii_lowercase().as_ref()),
    super::DerivedComponentName::Scheme => HttpMessageComponentValue::from(field_values[0].to_ascii_lowercase().as_ref()),
    super::DerivedComponentName::RequestTarget => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    super::DerivedComponentName::Path => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    super::DerivedComponentName::Query => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    super::DerivedComponentName::Status => HttpMessageComponentValue::from(field_values[0].to_string().as_ref()),
    super::DerivedComponentName::QueryParam => {
      let name = id.params.0.iter().find_map(|p| match p {
        HttpMessageComponentParam::Name(name) => Some(name),
        _ => None,
      });
      ensure!(name.is_some(), "query-param derived component requires name parameter");
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
    super::DerivedComponentName::SignatureParams => {
      let value = field_values[0].to_string();
      let opt_pair = value.trim().split_once('=');
      ensure!(opt_pair.is_some(), "invalid signature-params derived component");
      let (key, value) = opt_pair.unwrap();
      HttpMessageComponentValue::from((key, value))
    }
  };
  let component = HttpMessageComponent { id: id.clone(), value };
  Ok(component)
}

/// Build http field component from given id and its associated field values
/// NOTE: field_value must be ones of request for `req` param
pub(super) fn build_http_field_component(id: &HttpMessageComponentId, field_values: &[String]) -> anyhow::Result<HttpMessageComponent> {
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
      HttpMessageComponentParam::Bs => bail!("`bs` is not supported yet"),
      HttpMessageComponentParam::Req => {
        debug!("`req` is given for http field component");
      }
      HttpMessageComponentParam::Tr => bail!("`tr` is not supported yet"),
      HttpMessageComponentParam::Name(_) => bail!("`name` is only for derived component query-params"),
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

/// Handle `sf` parameter
fn handle_params_sf(field_values: &mut [String]) -> anyhow::Result<()> {
  let parsed_list = field_values
    .iter()
    .map(|v| {
      if let Ok(list) = Parser::parse_list(v.as_bytes()) {
        list.serialize_value()
      } else if let Ok(dict) = Parser::parse_dictionary(v.as_bytes()) {
        dict.serialize_value()
      } else {
        bail!("invalid structured field value for sf");
      }
      .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .collect::<Vec<_>>();

  ensure!(
    parsed_list.iter().all(|v| v.is_ok()),
    "Failed to parse structured field value"
  );
  field_values.iter_mut().zip(parsed_list).for_each(|(v, p)| {
    *v = p.unwrap();
  });

  Ok(())
}

/// Handle `key` parameter, returns new field values
fn handle_params_key_into(field_values: &[String], key: &str) -> anyhow::Result<Vec<String>> {
  let dicts = field_values
    .iter()
    .map(|v| Parser::parse_dictionary(v.as_bytes()))
    .collect::<Vec<_>>();
  ensure!(dicts.iter().all(|v| v.is_ok()), "Failed to parse structured field value");

  let found_entries = dicts
    .into_iter()
    .map(|v| v.unwrap())
    .filter_map(|dict| {
      dict.get(key).map(|v| {
        let sfvalue: sfv::List = vec![v.clone()];
        sfvalue
      })
    })
    .map(|v| v.serialize_value().map_err(|e| anyhow::anyhow!("{e}")))
    .collect::<Vec<_>>();

  ensure!(
    found_entries.iter().all(|v| v.is_ok()),
    "Failed to serialize structured field value"
  );

  let found_entries = found_entries.into_iter().map(|v| v.unwrap()).collect::<Vec<_>>();

  Ok(found_entries)
}

/* ------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------ */
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parser_test() {
    // Parsing structured field value of Item type.
    let item_header_input = "12.445;foo=bar";
    let item = Parser::parse_item(item_header_input.as_bytes()).unwrap();
    assert_eq!(item.serialize_value().unwrap(), item_header_input);

    // Parsing structured field value of List type.
    let list_header_input = "  1; a=tok, (\"foo\"   \"bar\" );baz, (  )";
    let list = Parser::parse_list(list_header_input.as_bytes()).unwrap();
    assert_eq!(list.serialize_value().unwrap(), "1;a=tok, (\"foo\" \"bar\");baz, ()");

    // Parsing structured field value of Dictionary type.
    let dict_header_input = "a=?0, b, c; foo=bar, rating=1.5, fruits=(apple pear), d";
    let dict = Parser::parse_dictionary(dict_header_input.as_bytes()).unwrap();
    assert_eq!(
      dict.serialize_value().unwrap(),
      "a=?0, b, c;foo=bar, rating=1.5, fruits=(apple pear), d"
    );
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
