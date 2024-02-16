use crate::error::{HttpSigError, HttpSigResult};
use sfv::{Parser, SerializeValue};

type IndexSet<K> = indexmap::IndexSet<K, fxhash::FxBuildHasher>;

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

impl TryFrom<(&str, &sfv::BareItem)> for HttpMessageComponentParam {
  type Error = HttpSigError;
  fn try_from((key, val): (&str, &sfv::BareItem)) -> Result<Self, Self::Error> {
    match key {
      "sf" => Ok(Self::Sf),
      "bs" => Ok(Self::Bs),
      "tr" => Ok(Self::Tr),
      "req" => Ok(Self::Req),
      "name" => {
        let name = val.as_str().ok_or(HttpSigError::InvalidComponentParam(
          "Invalid http field param: name".to_string(),
        ))?;
        Ok(Self::Name(name.to_string()))
      }
      "key" => {
        let key = val.as_str().ok_or(HttpSigError::InvalidComponentParam(
          "Invalid http field param: key".to_string(),
        ))?;
        Ok(Self::Key(key.to_string()))
      }
      _ => Err(HttpSigError::InvalidComponentParam(format!(
        "Invalid http field param: {key}"
      ))),
    }
  }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// Http message component parameters
pub struct HttpMessageComponentParams(pub IndexSet<HttpMessageComponentParam>);

impl std::hash::Hash for HttpMessageComponentParams {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    let mut params = self.0.iter().map(|v| v.clone().into()).collect::<Vec<String>>();
    params.sort();
    params.hash(state);
  }
}

impl TryFrom<&sfv::Parameters> for HttpMessageComponentParams {
  type Error = HttpSigError;
  fn try_from(val: &sfv::Parameters) -> Result<Self, Self::Error> {
    let hs = val
      .iter()
      .map(|(k, v)| HttpMessageComponentParam::try_from((k.as_str(), v)))
      .collect::<Result<IndexSet<_>, _>>()?;
    Ok(Self(hs))
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
/// Handle `sf` parameter
pub(super) fn handle_params_sf(field_values: &mut [String]) -> HttpSigResult<()> {
  let parsed_list = field_values
    .iter()
    .map(|v| {
      if let Ok(list) = Parser::parse_list(v.as_bytes()) {
        list.serialize_value()
      } else if let Ok(dict) = Parser::parse_dictionary(v.as_bytes()) {
        dict.serialize_value()
      } else {
        Err("invalid structured field value for sf")
      }
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| HttpSigError::InvalidComponentParam(format!("Failed to parse structured field value: {e}")))?;

  field_values.iter_mut().zip(parsed_list).for_each(|(v, p)| {
    *v = p;
  });

  Ok(())
}

/* ---------------------------------------------------------------- */
/// Handle `key` parameter, returns new field values
pub(super) fn handle_params_key_into(field_values: &[String], key: &str) -> HttpSigResult<Vec<String>> {
  let dicts = field_values
    .iter()
    .map(|v| Parser::parse_dictionary(v.as_bytes()))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| HttpSigError::InvalidComponentParam(format!("Failed to parse structured field value: {e}")))?;

  let found_entries = dicts
    .into_iter()
    .filter_map(|dict| {
      dict.get(key).map(|v| {
        let sfvalue: sfv::List = vec![v.clone()];
        sfvalue.serialize_value()
      })
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| HttpSigError::InvalidComponentParam(format!("Failed to serialize structured field value: {e}")))?;

  Ok(found_entries)
}

/* ---------------------------------------------------------------- */

mod tests {
  #[allow(unused)]
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
}
