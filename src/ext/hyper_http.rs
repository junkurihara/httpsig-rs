use super::{ContentDigestType, CONTENT_DIGEST_HEADER};
use crate::{
  message_component::{
    DerivedComponentName, HttpMessageComponent, HttpMessageComponentName, HttpMessageComponentParam,
    HttpMessageComponentValue,
  },
  signature_base::SignatureBase,
  signature_params::HttpSignatureParams,
};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use sha2::Digest;

// hyper's http specific extension to generate and verify http signature

/* --------------------------------------- */
#[async_trait]
trait HyperContentDigest: http_body::Body {
  /// Returns the bytes object of the body
  async fn into_bytes(self) -> std::result::Result<Bytes, Self::Error>
  where
    Self: Sized,
    Self::Data: Send,
  {
    let mut body_buf = self.collect().await?.aggregate();
    Ok(body_buf.copy_to_bytes(body_buf.remaining()))
  }

  /// Returns the content digest in base64
  async fn into_bytes_with_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> std::result::Result<(Bytes, String), Self::Error>
  where
    Self: Sized,
    Self::Data: Send,
  {
    let body_bytes = self.into_bytes().await?;
    let digest = match cd_type {
      ContentDigestType::Sha256 => {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&body_bytes);
        hasher.finalize().to_vec()
      }

      ContentDigestType::Sha512 => {
        let mut hasher = sha2::Sha512::new();
        hasher.update(&body_bytes);
        hasher.finalize().to_vec()
      }
    };

    Ok((body_bytes, general_purpose::STANDARD.encode(digest)))
  }
}

impl<T: ?Sized> HyperContentDigest for T where T: http_body::Body {}

/* --------------------------------------- */
#[async_trait]
/// A trait to set the http content digest in request in base64
pub trait HyperRequestContentDigest {
  type Error;
  async fn set_content_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> std::result::Result<Request<Full<Bytes>>, Self::Error>
  where
    Self: Sized;
}

#[async_trait]
/// A trait to set the http content digest in response in base64
pub trait HyperResponseContentDigest {
  type Error;
  async fn set_content_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> std::result::Result<Response<Full<Bytes>>, Self::Error>
  where
    Self: Sized;
}

#[async_trait]
impl<B> HyperRequestContentDigest for Request<B>
where
  B: Body + Send,
  <B as Body>::Data: Send,
{
  type Error = anyhow::Error;

  async fn set_content_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> std::result::Result<Request<Full<Bytes>>, Self::Error>
  where
    Self: Sized,
  {
    let (mut parts, body) = self.into_parts();
    let (body_bytes, digest) = body
      .into_bytes_with_digest(cd_type)
      .await
      .map_err(|_e| anyhow::anyhow!("Failed to generate digest"))?;
    let new_body = Full::new(body_bytes);

    parts
      .headers
      .insert(CONTENT_DIGEST_HEADER, format!("{cd_type}=:{digest}:").parse().unwrap());

    let new_req = Request::from_parts(parts, new_body);
    Ok(new_req)
  }
}

#[async_trait]
impl<B> HyperResponseContentDigest for Response<B>
where
  B: Body + Send,
  <B as Body>::Data: Send,
{
  type Error = anyhow::Error;

  async fn set_content_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> std::result::Result<Response<Full<Bytes>>, Self::Error>
  where
    Self: Sized,
  {
    let (mut parts, body) = self.into_parts();
    let (body_bytes, digest) = body
      .into_bytes_with_digest(cd_type)
      .await
      .map_err(|_e| anyhow::anyhow!("Failed to generate digest"))?;
    let new_body = Full::new(body_bytes);

    parts
      .headers
      .insert(CONTENT_DIGEST_HEADER, format!("{cd_type}=:{digest}:").parse().unwrap());

    let new_req = Response::from_parts(parts, new_body);
    Ok(new_req)
  }
}

/* --------------------------------------- */
#[async_trait]
/// A trait to set the http message signature from given http signature params
pub trait HyperRequestMessageSignature {
  type Error;
  async fn set_message_signature(
    &mut self,
    signature_params: &HttpSignatureParams,
  ) -> std::result::Result<(), Self::Error>
  where
    Self: Sized;
}

#[async_trait]
impl<D> HyperRequestMessageSignature for Request<D>
where
  D: Send + Body,
{
  type Error = anyhow::Error;

  async fn set_message_signature(
    &mut self,
    signature_params: &HttpSignatureParams,
  ) -> std::result::Result<(), Self::Error>
  where
    Self: Sized,
  {
    let component_lines = signature_params
      .covered_components
      .iter()
      .map(|component_id_str| {
        let component_id = HttpMessageComponentName::from(component_id_str.as_str());

        extract_component_from_request(self, &component_id)
      })
      .collect::<Vec<_>>();

    anyhow::ensure!(
      component_lines.iter().all(|c| c.is_ok()),
      "Failed to extract component lines"
    );
    let component_lines = component_lines.into_iter().map(|c| c.unwrap()).collect::<Vec<_>>();

    let signature_base = SignatureBase::try_new(&component_lines, signature_params);

    Ok(())
  }
}
/* --------------------------------------- */
/// Extract http message component from hyper http request
fn extract_component_from_request<B>(
  req: &Request<B>,
  target_component_id: &HttpMessageComponentName,
) -> Result<HttpMessageComponent, anyhow::Error> {
  let params = match &target_component_id {
    HttpMessageComponentName::HttpField(field_id) => &field_id.params,
    HttpMessageComponentName::Derived(derived_id) => &derived_id.params,
  };
  anyhow::ensure!(
    !params.0.contains(&HttpMessageComponentParam::Req),
    "`req` is not allowed in request"
  );

  let field_values = match &target_component_id {
    HttpMessageComponentName::HttpField(field_id) => {
      let field_values = req
        .headers()
        .get_all(&field_id.filed_name)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
      field_values
    }
    HttpMessageComponentName::Derived(derived_id) => {
      let url = url::Url::parse(&req.uri().to_string())?;
      let field_value = match derived_id.component_name {
        DerivedComponentName::Method => req.method().to_string(),
        DerivedComponentName::TargetUri => url.to_string(),
        DerivedComponentName::Authority => url.authority().to_string(),
        DerivedComponentName::Scheme => url.scheme().to_string(),
        DerivedComponentName::RequestTarget => match *req.method() {
          http::Method::CONNECT => url.authority().to_string(),
          http::Method::OPTIONS => "*".to_string(),
          _ => {
            let mut base = url.path().to_string();
            if let Some(query) = url.query() {
              base.push_str(&format!("?{query}"));
            }
            base
          }
        },
        DerivedComponentName::Path => url.path().to_string(),
        DerivedComponentName::Query => format!("?{}", url.query().unwrap_or("")),
        DerivedComponentName::QueryParam => {
          let query_pairs = url.query_pairs().collect::<Vec<_>>();
          println!("query_param: {:?}", query_pairs);

          todo!("not implemented yet") // TODO: dict
        }
        _ => panic!("invalid derived component name for request"),
      };
      vec![field_value]
    }
  };

  let component = HttpMessageComponent {
    name: target_component_id.clone(),
    value: HttpMessageComponentValue::from(""),
  };
  Ok(component)
}

/* --------------------------------------- */
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_extract_component_from_request() {
    let req = Request::builder()
      .method("GET")
      .uri("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")
      .header("date", "Sun, 09 May 2021 18:30:00 GMT")
      .header("content-type", "application/json")
      .body(())
      .unwrap();

    let component_id_method = HttpMessageComponentName::from("\"@method\"");
    let component = extract_component_from_request(&req, &component_id_method).unwrap();
    println!("{:?}", component);

    let component_id_query_param = HttpMessageComponentName::from("\"@query-param\"");
    let component = extract_component_from_request(&req, &component_id_query_param).unwrap();
    println!("{:?}", component);
    // let component = extract_component_from_request(&req, &component_id).unwrap();
    // assert_eq!(component.id, component_id);
    // assert_eq!(component.field_values, vec!["GET".to_string()]);

    // let component_id = HttpMessageComponentIdentifier::from("\"date\"");
    // let component = extract_component_from_request(&req, &component_id).unwrap();
    // assert_eq!(component.id, component_id);
    // assert_eq!(
    //   component.field_values,
    //   vec!["Sun, 09 May 2021 18:30:00 GMT".to_string()]
    // );

    // let component_id = HttpMessageComponentIdentifier::from("\"content-type\"");
    // let component = extract_component_from_request(&req, &component_id).unwrap();
    // assert_eq!(component.id, component_id);
    // assert_eq!(component.field_values, vec!["application/json".to_string()]);

    // let component_id = HttpMessageComponentIdentifier::from("\"@signature-params\"");
    // let component = extract_component_from_request(&req, &component_id).unwrap();
    // assert_eq!(component.id, component_id);
    // assert_eq!(component.field_values, vec!["".to_string()]);
  }

  #[tokio::test]
  async fn content_digest() {
    let body = Full::new(&b"{\"hello\": \"world\"}"[..]);
    let (_body_bytes, digest) = body.into_bytes_with_digest(&ContentDigestType::Sha256).await.unwrap();

    assert_eq!(digest, "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");

    let (_body_bytes, digest) = body.into_bytes_with_digest(&ContentDigestType::Sha512).await.unwrap();
    assert_eq!(
      digest,
      "WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew=="
    );
  }

  #[tokio::test]
  async fn hyper_request_test() {
    let body = Full::new(&b"{\"hello\": \"world\"}"[..]);

    let req = Request::builder()
      .method("GET")
      .uri("https://example.com/")
      .header("date", "Sun, 09 May 2021 18:30:00 GMT")
      .header("content-type", "application/json")
      .body(body)
      .unwrap();
    let req = req.set_content_digest(&ContentDigestType::Sha256).await.unwrap();

    assert!(req.headers().contains_key(CONTENT_DIGEST_HEADER));
    let digest = req.headers().get(CONTENT_DIGEST_HEADER).unwrap().to_str().unwrap();
    assert_eq!(
      digest,
      format!("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
    );
  }

  #[tokio::test]
  async fn hyper_response_test() {
    let body = Full::new(&b"{\"hello\": \"world\"}"[..]);

    let res = Response::builder()
      .status(200)
      .header("date", "Sun, 09 May 2021 18:30:00 GMT")
      .header("content-type", "application/json")
      .body(body)
      .unwrap();
    let res = res.set_content_digest(&ContentDigestType::Sha256).await.unwrap();

    assert!(res.headers().contains_key(CONTENT_DIGEST_HEADER));
    let digest = res.headers().get(CONTENT_DIGEST_HEADER).unwrap().to_str().unwrap();
    assert_eq!(
      digest,
      format!("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
    );
  }
}
