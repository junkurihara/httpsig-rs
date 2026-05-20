use std::fmt;

use crate::error::{HttpSigError, HttpSigResult};
use compact_str::{CompactString, ToCompactString};
use sfv::{FieldType, Parser};

type IndexSet<K> = indexmap::IndexSet<K, rustc_hash::FxBuildHasher>;

/* ---------------------------------------------------------------- */
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
/// Http message component parameters that appends with `;` in the signature input
/// https://datatracker.ietf.org/doc/html/rfc9421#secion-2.1
pub enum HttpMessageComponentParam {
  /// sf: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1.1
  Sf,
  /// key: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1.2
  /// This will be encoded to `;key="..."` in the signature input
  Key(CompactString),
  /// bs: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1.3
  Bs,
  // tr: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1.4
  Tr,
  // req: https://datatracker.ietf.org/doc/html/rfc9421#section-2.4
  Req,
  // name: https://datatracker.ietf.org/doc/html/rfc9421#name-query-parameters
  /// This will be encoded to `;name="..."` in the signature input
  Name(CompactString),
}

impl fmt::Display for HttpMessageComponentParam {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      HttpMessageComponentParam::Sf => write!(f, "sf")?,
      HttpMessageComponentParam::Key(key) => write!(f, "key=\"{key}\"")?,
      HttpMessageComponentParam::Bs => write!(f, "bs")?,
      HttpMessageComponentParam::Tr => write!(f, "tr")?,
      HttpMessageComponentParam::Req => write!(f, "req")?,
      HttpMessageComponentParam::Name(name) => write!(f, "name=\"{name}\"")?,
    }
    Ok(())
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
        let name = val.as_string().ok_or(HttpSigError::InvalidComponentParam(
          "Invalid http field param: name".into(),
        ))?;
        Ok(Self::Name(name.as_str().to_compact_string()))
      }
      "key" => {
        let key = val.as_string().ok_or(HttpSigError::InvalidComponentParam(
          "Invalid http field param: key".into(),
        ))?;
        Ok(Self::Key(key.as_str().to_compact_string()))
      }
      _ => Err(HttpSigError::InvalidComponentParam(
        format!("Invalid http field param: {key}").into(),
      )),
    }
  }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// Http message component parameters
pub struct HttpMessageComponentParams(pub IndexSet<HttpMessageComponentParam>);

impl std::hash::Hash for HttpMessageComponentParams {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    let mut params = self
      .0
      .iter()
      .map(|p| p.to_compact_string())
      .collect::<Vec<CompactString>>();
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
      for param in self.0.iter() {
        write!(f, ";{}", param)?;
      }
    }
    Ok(())
  }
}

/* ---------------------------------------------------------------- */
/// Handle `sf` parameter
pub(super) fn handle_params_sf(field_values: &mut [CompactString]) -> HttpSigResult<()> {
  let parsed_list = field_values
    .iter()
    .map(|v| {
      if let Ok(list) = Parser::new(v).parse::<sfv::List>() {
        list
          .serialize()
          .ok_or("Failed to parse structured field value: failed to serialize structured field value for sf")
      } else if let Ok(dict) = Parser::new(v).parse::<sfv::Dictionary>() {
        dict
          .serialize()
          .ok_or("Failed to parse structured field value: failed to serialize structured field value for sf")
      } else {
        Err("Failed to parse structured field value: invalid structured field value for sf")
      }
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| {
      HttpSigError::InvalidComponentParam(e.into())
    })?;

  field_values.iter_mut().zip(parsed_list).for_each(|(v, p)| {
    v.clear();
    v.push_str(&p);
  });

  Ok(())
}

/* ---------------------------------------------------------------- */
/// Handle `key` parameter, returns new field values
pub(super) fn handle_params_key_into(
  field_values: &[CompactString],
  key: &str,
) -> HttpSigResult<Vec<CompactString>> {
  let dicts = field_values
    .iter()
    .map(|v| Parser::new(v.as_str()).parse() as Result<sfv::Dictionary, _>)
    // Parser::parse_dictionary(v.as_bytes()))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| {
      HttpSigError::InvalidComponentParam(
        format!("Failed to parse structured field value: {e}").into(),
      )
    })?;

  let found_entries = dicts
    .into_iter()
    .filter_map(|dict| {
      dict.get(key).map(|v| {
        let sfvalue: sfv::List = vec![v.clone()];
        // sfvalue.serialize_value()
        sfvalue
          .serialize()
          .as_ref()
          .map(ToCompactString::to_compact_string)
      })
    })
    .collect::<Option<Vec<_>>>()
    .ok_or_else(|| {
      HttpSigError::InvalidComponentParam("Failed to serialize structured field value".into())
    })?;

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
    let item = Parser::new(item_header_input).parse::<sfv::Item>().unwrap();
    assert_eq!(item.serialize(), item_header_input);

    // Parsing structured field value of List type.
    let list_header_input = "  1; a=tok, (\"foo\"   \"bar\" );baz, (  )";
    let list = Parser::new(list_header_input).parse::<sfv::List>().unwrap();
    assert_eq!(
      list.serialize().unwrap(),
      "1;a=tok, (\"foo\" \"bar\");baz, ()"
    );

    // Parsing structured field value of Dictionary type.
    let dict_header_input = "a=?0, b, c; foo=bar, rating=1.5, fruits=(apple pear), d";
    let dict = Parser::new(dict_header_input)
      .parse::<sfv::Dictionary>()
      .unwrap();
    assert_eq!(
      dict.serialize().unwrap(),
      "a=?0, b, c;foo=bar, rating=1.5, fruits=(apple pear), d"
    );
  }
}
