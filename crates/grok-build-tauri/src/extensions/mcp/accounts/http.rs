//! One-request HTTPS clients pin every classified address and never retry or redirect.
use super::auth_contract::Endpoint;
use grok_build_plus_host::mcp_pin_public_addresses as pin_addresses;
use reqwest::{Client, Method};
use rustls_platform_verifier::BuilderVerifierExt as _;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

pub(crate) enum RequestBody {
    Form(Vec<u8>),
    Json(Vec<u8>),
}

pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) challenges: Vec<String>,
    pub(crate) body: Vec<u8>,
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.body.fill(0);
    }
}

pub(crate) async fn request(
    endpoint: &Endpoint,
    form: Option<RequestBody>,
    cancelled: &AtomicBool,
) -> Result<Reply, String> {
    let operation = async {
        let host = endpoint
            .url()
            .host_str()
            .ok_or("OAuth endpoint has no host.")?;
        let port = endpoint
            .url()
            .port_or_known_default()
            .ok_or("OAuth endpoint has no port.")?;
        let addresses = resolve(host, port).await?;
        let client = client(host, &addresses)?;
        let mut request = client
            .request(
                if form.is_some() {
                    Method::POST
                } else {
                    Method::GET
                },
                endpoint.url().clone(),
            )
            .header("Accept", "application/json");
        if let Some(form) = form {
            let (content_type, bytes) = match form {
                RequestBody::Form(bytes) => ("application/x-www-form-urlencoded", bytes),
                RequestBody::Json(bytes) => ("application/json", bytes),
            };
            if bytes.len() > 16 * 1024 {
                return Err("OAuth request body exceeded its bound.".into());
            }
            request = request.header("Content-Type", content_type).body(bytes);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "OAuth request failed; no request will be automatically repeated.")?;
        validate_headers(&response)?;
        let headers = response.headers();
        let status = response.status().as_u16();
        if response.status().is_redirection() {
            return Err("OAuth redirects require a new explicit endpoint review.".into());
        }
        let challenges = headers
            .get_all("www-authenticate")
            .iter()
            .map(|v| {
                v.to_str()
                    .map(str::to_owned)
                    .map_err(|_| "OAuth challenge is not text.")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut result = Reply {
            status,
            challenges,
            body: Vec::new(),
        };
        if status == 401 || status == 403 || status == 404 || status == 405 {
            return Ok(result);
        }
        let json = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return Err("OAuth response is not JSON.".into());
        }
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "OAuth response ended before completion.")?
        {
            if result.body.len().saturating_add(chunk.len()) > 64 * 1024 {
                return Err("OAuth response body exceeded its bound.".into());
            }
            result.body.extend_from_slice(&chunk);
        }
        Ok(result)
    };
    let mut bounded = Box::pin(tokio::time::timeout(Duration::from_secs(15), operation));
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(
                "OAuth operation was cancelled; submitted requests are not replayed.".into(),
            );
        }
        if let Ok(result) = tokio::time::timeout(Duration::from_millis(100), &mut bounded).await {
            return result.map_err(|_| "OAuth operation exceeded its deadline.".to_owned())?;
        }
    }
}

fn validate_headers(response: &reqwest::Response) -> Result<(), String> {
    let headers = response.headers();
    if headers.len() > 64
        || headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > 16 * 1024
    {
        return Err("OAuth response headers exceeded their bound.".into());
    }
    for name in [
        "content-type",
        "content-length",
        "content-encoding",
        "location",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err("OAuth response framing is ambiguous.".into());
        }
    }
    if headers
        .get("content-encoding")
        .is_some_and(|v| v.as_bytes() != b"identity")
    {
        return Err("Compressed OAuth replies are not admitted.".into());
    }
    if response.content_length().is_some_and(|n| n > 64 * 1024) {
        return Err("OAuth response body exceeded its bound.".into());
    }
    Ok(())
}

fn client(host: &str, addresses: &[SocketAddr]) -> Result<Client, String> {
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "OAuth TLS versions unavailable.")?
    .with_platform_verifier()
    .map_err(|_| "OAuth platform certificate verification unavailable.")?
    .with_no_client_auth();
    Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .resolve_to_addrs(host, addresses)
        .pool_max_idle_per_host(0)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "OAuth pinned HTTPS client could not be created.".into())
}

static RESOLVERS: AtomicUsize = AtomicUsize::new(0);

pub(super) async fn addresses(
    endpoint: &Endpoint,
    cancel: &AtomicBool,
) -> Result<Vec<SocketAddr>, String> {
    let mut pending = Box::pin(tokio::time::timeout(
        Duration::from_secs(15),
        resolve(
            endpoint
                .url()
                .host_str()
                .ok_or("MCP endpoint has no host.")?,
            endpoint
                .url()
                .port_or_known_default()
                .ok_or("MCP endpoint has no port.")?,
        ),
    ));
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err("MCP address admission was cancelled.".into());
        }
        if let Ok(result) = tokio::time::timeout(Duration::from_millis(100), &mut pending).await {
            return result.map_err(|_| "MCP address admission timed out.".to_owned())?;
        }
    }
}
struct ResolverReservation;
impl Drop for ResolverReservation {
    fn drop(&mut self) {
        RESOLVERS.fetch_sub(1, Ordering::AcqRel);
    }
}
async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    RESOLVERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 2).then_some(n + 1)
        })
        .map_err(|_| "OAuth DNS capacity remains occupied.")?;
    let reserved = ResolverReservation;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    tokio::task::spawn_blocking(move || {
        // Retained inside the actual blocking lookup, including after cancellation
        // drops its async receiver. A stuck resolver cannot admit unlimited threads.
        let _reserved = reserved;
        let addresses = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| "OAuth endpoint resolution failed.")?;
        pin_addresses(addresses.take(65), port)
    })
    .await
    .map_err(|_| "OAuth resolver failed.".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_https_refuses_before_any_tcp_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = Endpoint::parse(&format!(
            "https://{}/metadata",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(request(&endpoint, None, &AtomicBool::new(false)));
        assert!(result.err().unwrap().contains("private"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(RESOLVERS.load(Ordering::Acquire), 0);
    }
    #[test]
    fn preexisting_cancel_cannot_start_discovery_or_consume_resolver_capacity() {
        let endpoint = Endpoint::parse("https://example.invalid/metadata").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(request(&endpoint, None, &AtomicBool::new(true)));
        assert!(result.err().unwrap().contains("cancelled"));
        assert_eq!(RESOLVERS.load(Ordering::Acquire), 0);
    }
}
