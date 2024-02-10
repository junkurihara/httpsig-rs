use super::{ContentDigestType, CONTENT_DIGEST_HEADER};
use anyhow::ensure;
use base64::{engine::general_purpose, Engine as _};
use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use sfv::FromStr;
use sha2::Digest;
use std::future::Future;

// hyper's http specific extension to generate and verify http signature

/* --------------------------------------- */
pub trait ContentDigest: http_body::Body {
  /// Returns the bytes object of the body
  fn into_bytes(self) -> impl Future<Output = Result<Bytes, Self::Error>> + Send
  where
    Self: Sized + Send,
    Self::Data: Send,
  {
    async {
      let mut body_buf = self.collect().await?.aggregate();
      Ok(body_buf.copy_to_bytes(body_buf.remaining()))
    }
  }

  /// Returns the content digest in base64
  fn into_bytes_with_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> impl Future<Output = Result<(Bytes, String), Self::Error>> + Send
  where
    Self: Sized + Send,
    Self::Data: Send,
  {
    async move {
      let body_bytes = self.into_bytes().await?;
      let digest = derive_digest(&body_bytes, cd_type);

      Ok((body_bytes, general_purpose::STANDARD.encode(digest)))
    }
  }

  /// Verifies the consistency between self and given content-digest in &[u8]
  fn verify_digest(self, cd_type: &ContentDigestType, _cd: &[u8]) -> impl Future<Output = Result<bool, Self::Error>> + Send
  where
    Self: Sized + Send,
    Self::Data: Send,
  {
    async move {
      let body_bytes = self.into_bytes().await?;
      let digest = derive_digest(&body_bytes, cd_type);

      Ok(matches!(digest, _cd))
    }
  }
}

/// Returns the digest of the given body in Vec<u8>
fn derive_digest(body_bytes: &Bytes, cd_type: &ContentDigestType) -> Vec<u8> {
  match cd_type {
    ContentDigestType::Sha256 => {
      let mut hasher = sha2::Sha256::new();
      hasher.update(body_bytes);
      hasher.finalize().to_vec()
    }

    ContentDigestType::Sha512 => {
      let mut hasher = sha2::Sha512::new();
      hasher.update(body_bytes);
      hasher.finalize().to_vec()
    }
  }
}

impl<T: ?Sized> ContentDigest for T where T: http_body::Body {}

/* --------------------------------------- */
/// A trait to set the http content digest in request in base64
pub trait RequestContentDigest {
  type Error;
  fn set_content_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> impl Future<Output = Result<Request<Full<Bytes>>, Self::Error>> + Send
  where
    Self: Sized;
  fn verify_content_digest(self) -> impl Future<Output = Result<bool, Self::Error>> + Send
  where
    Self: Sized;
}

/// A trait to set the http content digest in response in base64
pub trait ResponseContentDigest {
  type Error;
  fn set_content_digest(
    self,
    cd_type: &ContentDigestType,
  ) -> impl Future<Output = Result<Response<Full<Bytes>>, Self::Error>> + Send
  where
    Self: Sized;
  fn verify_content_digest(self) -> impl Future<Output = Result<bool, Self::Error>> + Send
  where
    Self: Sized;
}

impl<B> RequestContentDigest for Request<B>
where
  B: Body + Send,
  <B as Body>::Data: Send,
{
  type Error = anyhow::Error;

  async fn set_content_digest(self, cd_type: &ContentDigestType) -> Result<Request<Full<Bytes>>, Self::Error>
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

  async fn verify_content_digest(self) -> Result<bool, Self::Error>
  where
    Self: Sized,
  {
    let header_map = self.headers();
    let (cd_type, cd) = extract_content_digest(header_map).await?;
    let (_, body) = self.into_parts();
    body
      .verify_digest(&cd_type, &cd)
      .await
      .map_err(|_e| anyhow::anyhow!("Failed to verify digest"))
  }
}

impl<B> ResponseContentDigest for Response<B>
where
  B: Body + Send,
  <B as Body>::Data: Send,
{
  type Error = anyhow::Error;

  async fn set_content_digest(self, cd_type: &ContentDigestType) -> Result<Response<Full<Bytes>>, Self::Error>
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
  async fn verify_content_digest(self) -> Result<bool, Self::Error>
  where
    Self: Sized,
  {
    let header_map = self.headers();
    let (cd_type, cd) = extract_content_digest(header_map).await?;
    let (_, body) = self.into_parts();
    body
      .verify_digest(&cd_type, &cd)
      .await
      .map_err(|_e| anyhow::anyhow!("Failed to verify digest"))
  }
}

async fn extract_content_digest(header_map: &http::HeaderMap) -> anyhow::Result<(ContentDigestType, Vec<u8>)> {
  let content_digest_header = header_map
    .get(CONTENT_DIGEST_HEADER)
    .ok_or(anyhow::anyhow!("Content-Digest header not found"))?
    .to_str()?;
  let indexmap = sfv::Parser::parse_dictionary(content_digest_header.as_bytes())
    .map_err(|e| anyhow::anyhow!("Failed to parse Content-Digest header: {e}"))?;
  ensure!(indexmap.len() == 1, "Content-Digest header should have only one value");
  let (cd_type, cd) = indexmap.iter().next().unwrap();
  let cd_type = ContentDigestType::from_str(cd_type).map_err(|e| anyhow::anyhow!("Invalid Content-Digest type: {e}"))?;
  ensure!(
    matches!(
      cd,
      sfv::ListEntry::Item(sfv::Item {
        bare_item: sfv::BareItem::ByteSeq(_),
        ..
      })
    ),
    "Invalid Content-Digest value"
  );
  let cd = match cd {
    sfv::ListEntry::Item(sfv::Item {
      bare_item: sfv::BareItem::ByteSeq(cd),
      ..
    }) => cd,
    _ => unreachable!(),
  };
  Ok((cd_type, cd.to_owned()))
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

    let verified = req.verify_content_digest().await.unwrap();
    assert!(verified);
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

    let verified = res.verify_content_digest().await.unwrap();
    assert!(verified);
  }
}
