#[cfg(feature = "doh-upstream")]
use crate::error::DnsError;
#[cfg(feature = "doh-upstream")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "doh-upstream")]
use hyper::body::Bytes;
#[cfg(feature = "doh-upstream")]
use hyper::{Method, Request};
#[cfg(feature = "doh-upstream")]
use hyper_rustls::HttpsConnectorBuilder;
#[cfg(feature = "doh-upstream")]
use hyper_util::client::legacy::Client;
#[cfg(feature = "doh-upstream")]
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(feature = "doh-upstream")]
use hyper_util::rt::TokioExecutor;
#[cfg(feature = "doh-upstream")]
use lanforge_types::network::dns::upstream::UpstreamTarget;
#[cfg(feature = "doh-upstream")]
use std::time::Duration;

#[cfg(feature = "doh-upstream")]
pub struct DohClient {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
}

#[cfg(feature = "doh-upstream")]
impl DohClient {
    #[must_use]
    pub fn new() -> Self {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(https);

        Self { client }
    }

    pub async fn resolve(&self, target: &UpstreamTarget, data: &[u8]) -> Result<Vec<u8>, DnsError> {
        let hostname = target.hostname.as_deref().unwrap_or("dns.google");
        let uri = format!("https://{}/dns-query", hostname);

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(Full::new(Bytes::copy_from_slice(data)))
            .map_err(|e| DnsError::Generic(e.to_string()))?;

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| DnsError::Generic(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(DnsError::Generic(format!(
                "DoH server returned status {}",
                resp.status()
            )));
        }

        let body = resp
            .collect()
            .await
            .map_err(|e| DnsError::Generic(e.to_string()))?
            .to_bytes();
        Ok(body.to_vec())
    }
}

#[cfg(feature = "doh-upstream")]
impl Default for DohClient {
    fn default() -> Self {
        Self::new()
    }
}
