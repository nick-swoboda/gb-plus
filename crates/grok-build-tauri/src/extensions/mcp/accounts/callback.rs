//! An owned loopback listener with finite attempts, input, waits and generic replies.
use super::flow::{Exchange, Flow};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) struct Callback(TcpListener);
impl Callback {
    pub(crate) fn bind() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|_| "Cannot reserve an OAuth callback port.")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "Cannot bound the OAuth callback listener.")?;
        Ok(Self(listener))
    }
    pub(crate) fn port(&self) -> Result<u16, String> {
        self.0
            .local_addr()
            .map(|a| a.port())
            .map_err(|_| "OAuth callback port is unavailable.".into())
    }
    pub(crate) fn wait(self, mut flow: Flow, cancel: &AtomicBool) -> Result<Exchange, String> {
        let started = Instant::now();
        let mut attempts = 0;
        while started.elapsed() < Duration::from_mins(5) {
            if cancel.load(Ordering::Acquire) {
                return Err("MCP sign-in was cancelled.".into());
            }
            match self.0.accept() {
                Ok((mut stream, peer)) => {
                    attempts += 1;
                    if attempts > 8 || !peer.ip().is_loopback() {
                        return Err("OAuth callback attempts exceeded their bound.".into());
                    }
                    let request = read_request(&mut stream, cancel);
                    let result = request.and_then(|bytes| flow.accept_callback(&bytes));
                    let success = result.is_ok();
                    respond(&mut stream, success);
                    if success || flow.consumed() {
                        return result;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return Err("OAuth callback listener failed.".into()),
            }
        }
        Err("MCP sign-in expired. Start a new explicit attempt.".into())
    }
}

fn read_request(stream: &mut TcpStream, cancel: &AtomicBool) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|_| "Cannot bound the OAuth callback read.")?;
    stream
        .set_write_timeout(Some(Duration::from_millis(100)))
        .map_err(|_| "Cannot bound the OAuth callback reply.")?;
    let started = Instant::now();
    let mut bytes = Vec::new();
    loop {
        if cancel.load(Ordering::Acquire) || started.elapsed() > Duration::from_secs(2) {
            return Err("OAuth callback input was cancelled or timed out.".into());
        }
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => return Err("OAuth callback input ended early.".into()),
            Ok(n) => {
                if bytes.len().saturating_add(n) > 16 * 1024 {
                    return Err("OAuth callback input exceeded its bound.".into());
                }
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.windows(4).any(|b| b == b"\r\n\r\n") {
                    return Ok(bytes);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err("OAuth callback input failed.".into()),
        }
    }
}
fn respond(stream: &mut TcpStream, success: bool) {
    let (status, body) = if success {
        ("200 OK", "Authorization received. Return to GB Plus.")
    } else {
        (
            "400 Bad Request",
            "This authorization callback was not accepted.",
        )
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::super::auth_contract::{Endpoint, issuer_metadata};
    use super::*;
    use serde_json::json;
    #[test]
    fn a_real_loopback_callback_returns_one_bound_exchange_without_echoing_secrets() {
        let callback = Callback::bind().unwrap();
        let port = callback.port().unwrap();
        let issuer = Endpoint::parse("https://issuer.example/").unwrap();
        let metadata = issuer_metadata(&issuer, &serde_json::to_vec(&json!({
            "issuer":issuer.text(),"authorization_endpoint":"https://issuer.example/authorize",
            "token_endpoint":"https://issuer.example/token","code_challenge_methods_supported":["S256"],
            "response_types_supported":["code"],"token_endpoint_auth_methods_supported":["none"]
        })).unwrap()).unwrap();
        let flow = Flow::new(
            metadata,
            Endpoint::parse("https://resource.example/mcp").unwrap(),
            vec![],
            "fixture-client".into(),
            port,
        )
        .unwrap();
        let authorization = flow.authorization_url().unwrap();
        let state = authorization
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        let path = flow.redirect().path().to_owned();
        let worker = std::thread::spawn(move || callback.wait(flow, &AtomicBool::new(false)));
        let mut browser = TcpStream::connect(("127.0.0.1", port)).unwrap();
        browser
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        browser.write_all(format!("GET {path}?state={state}&code=synthetic-code HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).unwrap();
        let mut reply = String::new();
        browser.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!reply.contains(&state));
        assert!(!reply.contains("synthetic-code"));
        let exchange = worker.join().unwrap().unwrap();
        assert_eq!(exchange.endpoint.text(), "https://issuer.example/token");
        assert!(exchange.body.text().contains("code=synthetic-code"));
        assert!(
            exchange
                .body
                .text()
                .contains("resource=https%3A%2F%2Fresource.example%2Fmcp")
        );
    }

    #[test]
    fn callback_ownership_is_loopback_only_and_drop_releases_its_port() {
        let callback = Callback::bind().unwrap();
        let address = callback.0.local_addr().unwrap();
        assert_eq!(address.ip().to_string(), "127.0.0.1");
        assert_ne!(callback.port().unwrap(), 0);
        assert!(TcpListener::bind(address).is_err());
        drop(callback);
        assert!(TcpListener::bind(address).is_ok());
    }
    #[test]
    fn incomplete_callback_and_preexisting_cancel_are_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        sender.write_all(b"GET / HTTP/1.1\r\n").unwrap();
        assert!(read_request(&mut receiver, &AtomicBool::new(true)).is_err());
        drop(sender);
        assert!(read_request(&mut receiver, &AtomicBool::new(false)).is_err());
    }
}
