use super::{ContentDigestType, CONTENT_DIGEST_HEADER};
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
trait ContentDigest: http_body::Body {
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
  async fn into_bytes_with_digest(self, cd_type: &ContentDigestType) -> std::result::Result<(Bytes, String), Self::Error>
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

impl<T: ?Sized> ContentDigest for T where T: http_body::Body {}

/* --------------------------------------- */
#[async_trait]
/// A trait to set the http content digest in request in base64
pub trait RequestContentDigest {
  type Error;
  async fn set_content_digest(self, cd_type: &ContentDigestType) -> std::result::Result<Request<Full<Bytes>>, Self::Error>
  where
    Self: Sized;
}

#[async_trait]
/// A trait to set the http content digest in response in base64
pub trait HyperResponseContentDigest {
  type Error;
  async fn set_content_digest(self, cd_type: &ContentDigestType) -> std::result::Result<Response<Full<Bytes>>, Self::Error>
  where
    Self: Sized;
}

#[async_trait]
impl<B> RequestContentDigest for Request<B>
where
  B: Body + Send,
  <B as Body>::Data: Send,
{
  type Error = anyhow::Error;

  async fn set_content_digest(self, cd_type: &ContentDigestType) -> std::result::Result<Request<Full<Bytes>>, Self::Error>
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

  async fn set_content_digest(self, cd_type: &ContentDigestType) -> std::result::Result<Response<Full<Bytes>>, Self::Error>
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
#[cfg(test)]
mod tests {
  use super::*;

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
    assert_eq!(digest, format!("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"));
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
    assert_eq!(digest, format!("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"));
  }
}
