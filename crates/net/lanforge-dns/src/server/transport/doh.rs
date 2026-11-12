#[cfg(feature = "doh-upstream")]
use crate::error::DnsError;
#[cfg(feature = "doh-upstream")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "doh-upstream")]
use hyper::body::Bytes;
#[cfg(feature = "doh-upstream")]
use hyper::{Method, Request, Uri};
#[cfg(feature = "doh-upstream")]
use hyper_rustls::HttpsConnectorBuilder;
#[cfg(feature = "doh-upstream")]
use hyper_util::client::legacy::Client;
#[cfg(feature = "doh-upstream")]
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(feature = "doh-upstream")]
use hyper_util::client::legacy::connect::dns::Name;
#[cfg(feature = "doh-upstream")]
use hyper_util::rt::TokioExecutor;
#[cfg(feature = "doh-upstream")]
use lanforge_types::network::dns::upstream::UpstreamTarget;
#[cfg(feature = "doh-upstream")]
use std::convert::Infallible;
#[cfg(feature = "doh-upstream")]
use std::future::{Ready, ready};
#[cfg(feature = "doh-upstream")]
use std::iter::{Once, once};
#[cfg(feature = "doh-upstream")]
use std::net::SocketAddr;
#[cfg(feature = "doh-upstream")]
use std::task::{Context, Poll};
#[cfg(feature = "doh-upstream")]
use std::time::Duration;
#[cfg(feature = "doh-upstream")]
use tower_service::Service;

/// Answers every name with the upstream's address: the URL's host is only the TLS and `Host`
/// name, never looked up through the system resolver (which can be this DNS itself).
#[cfg(feature = "doh-upstream")]
#[derive(Clone, Copy)]
struct FixedAddr(SocketAddr);

#[cfg(feature = "doh-upstream")]
impl Service<Name> for FixedAddr {
    type Response = Once<SocketAddr>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Name) -> Self::Future {
        ready(Ok(once(self.0)))
    }
}

#[cfg(feature = "doh-upstream")]
pub struct DohClient {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector<FixedAddr>>, Full<Bytes>>,
    uri: Uri,
}

#[cfg(feature = "doh-upstream")]
impl DohClient {
    /// A client for `target`'s URL (its TLS name, or the address itself, and its path) that
    /// connects to `addr`.
    pub fn new(target: &UpstreamTarget, addr: SocketAddr) -> Result<Self, DnsError> {
        let host = target.hostname.clone().unwrap_or_else(|| match addr {
            SocketAddr::V4(a) => a.ip().to_string(),
            SocketAddr::V6(a) => format!("[{}]", a.ip()),
        });
        let uri = format!("https://{host}:{}{}", addr.port(), target.doh_path())
            .parse()
            .map_err(|e| DnsError::Generic(format!("DoH URL: {e}")))?;

        let mut http = HttpConnector::new_with_resolver(FixedAddr(addr));
        http.enforce_http(false);
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(https);

        Ok(Self { client, uri })
    }

    pub async fn resolve(&self, data: &[u8]) -> Result<Vec<u8>, DnsError> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
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
