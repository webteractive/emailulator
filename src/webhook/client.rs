//! Posting one webhook: HTTP/1.1 over TCP, or over TLS for https, one request
//! per connection. Webhooks are rare and each goes out on its own, so there is
//! no pool to keep.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header;
use hyper_util::rt::TokioIo;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{CryptoProvider, ring};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

/// How long an endpoint has to answer, connection included.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// How much of an answer's body is kept, for the delivery log.
const MAX_RESPONSE: usize = 2048;

/// Where a webhook may be posted.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Allow endpoints on this machine and on private networks. Always so for
    /// an unprotected server on this machine only; on one that others may reach
    /// it must be asked for, or anyone who may add a webhook could make the
    /// server probe its own network.
    pub allow_private: bool,
}

/// What the endpoint said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// The start of the body.
    pub body: String,
}

/// One POST to make.
pub struct Post<'a> {
    pub endpoint: &'a str,
    pub body: &'a str,
    pub headers: &'a [(&'static str, String)],
    pub verify_tls: bool,
}

/// Post, and wait at most [`TIMEOUT`] for the answer.
pub async fn post(post: Post<'_>, policy: Policy) -> Result<Answer> {
    tokio::time::timeout(TIMEOUT, send(post, policy))
        .await
        .map_err(|_| anyhow!("no answer within {} seconds", TIMEOUT.as_secs()))?
}

/// Whether an address is one anybody may reach: not this machine, not a
/// private or link-local network, not an unspecified or broadcast address.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // Shared address space, used by carrier-grade NAT and Tailscale.
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                // Unique local, fc00::/7, and link-local, fe80::/10.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

async fn send(post: Post<'_>, policy: Policy) -> Result<Answer> {
    let uri: hyper::Uri = post.endpoint.parse().context("the endpoint is not a URL")?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => bail!("the endpoint is not an http or https URL"),
    };
    let authority = uri.authority().context("the endpoint has no host")?.clone();
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });

    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("looking up {host}"))?
        .collect();
    let allowed: Vec<SocketAddr> = resolved
        .iter()
        .copied()
        .filter(|addr| policy.allow_private || public(addr.ip()))
        .collect();
    if allowed.is_empty() {
        if resolved.is_empty() {
            bail!("{host} has no address");
        }
        bail!(
            "{host} is on this machine or a private network, which this server does not post \
             to; start it with --allow-private-webhooks to allow that"
        );
    }

    // Connect to an address that was checked, rather than look the name up
    // again: a second answer could name somewhere else.
    let mut last_error = None;
    let mut stream = None;
    for addr in allowed {
        match TcpStream::connect(addr).await {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some(stream) = stream else {
        let error = last_error.map_or_else(|| "no address".to_string(), |e| e.to_string());
        bail!("could not connect to {authority}: {error}");
    };

    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let mut request = hyper::Request::post(path)
        .header(header::HOST, authority.as_str())
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            concat!("emailulator/", env!("CARGO_PKG_VERSION")),
        );
    for (name, value) in post.headers {
        request = request.header(*name, value);
    }
    let request = request.body(Full::new(Bytes::from(post.body.to_owned())))?;

    if https {
        let config = tls_config(post.verify_tls)?;
        let name = ServerName::try_from(host.to_string())
            .with_context(|| format!("`{host}` is not a name TLS can check"))?;
        let stream = TlsConnector::from(config)
            .connect(name, stream)
            .await
            .map_err(|error| anyhow!("TLS with {authority} failed: {error}"))?;
        exchange(stream, request).await
    } else {
        exchange(stream, request).await
    }
}

async fn exchange<S>(stream: S, request: hyper::Request<Full<Bytes>>) -> Result<Answer>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("starting HTTP")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(request)
        .await
        .context("sending the request")?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut kept = Vec::new();
    while kept.len() < MAX_RESPONSE {
        // An answer that breaks off still has its status; keep what came.
        let Some(Ok(frame)) = body.frame().await else {
            break;
        };
        if let Some(data) = frame.data_ref() {
            let room = MAX_RESPONSE - kept.len();
            kept.extend_from_slice(&data[..data.len().min(room)]);
        }
    }
    Ok(Answer {
        status,
        body: String::from_utf8_lossy(&kept).into_owned(),
    })
}

fn tls_config(verify: bool) -> Result<Arc<ClientConfig>> {
    static VERIFIED: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    static UNVERIFIED: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    let cell = if verify { &VERIFIED } else { &UNVERIFIED };
    cell.get_or_init(|| build_tls_config(verify).map_err(|e| format!("{e:#}")))
        .clone()
        .map_err(|e| anyhow!("setting up TLS: {e}"))
}

fn build_tls_config(verify: bool) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let mut config = if verify {
        builder.with_platform_verifier()?.with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts whatever certificate the endpoint shows, for one whose owner turned
/// verification off: a self-signed certificate on a development machine.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_local_addresses_are_told_apart() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.1.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!public(private.parse().unwrap()), "{private}");
        }
        for open in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(public(open.parse().unwrap()), "{open}");
        }
    }

    #[tokio::test]
    async fn an_exposed_server_refuses_private_endpoints() {
        let error = post(
            Post {
                endpoint: "http://127.0.0.1:9/hook",
                body: "{}",
                headers: &[],
                verify_tls: true,
            },
            Policy {
                allow_private: false,
            },
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("--allow-private-webhooks"),
            "{error}"
        );
    }

    #[test]
    fn both_tls_configurations_build() {
        assert!(tls_config(true).is_ok());
        assert!(tls_config(false).is_ok());
    }
}
