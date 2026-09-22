//! Explicit fixed-hash plugin archives use the admitted TLS and HTTP parser.

use super::{
    Read, Write, connect_https, copy_exact_body, decode_sha256, parse_https_target, read_http_head,
    tls_config,
};

pub(crate) fn fetch(url: &str, byte_len: u64, sha256: &str) -> Result<Vec<u8>, String> {
    if byte_len == 0
        || byte_len > 64 * 1024 * 1024
        || sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Pin the archive's exact byte length (up to 64 MiB) and lowercase SHA-256 before download.".into());
    }
    if url.len() > 3072
        || !url.is_ascii()
        || url
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || url.contains(['?', '#'])
    {
        return Err(
            "Use a direct HTTPS archive URL without credentials, query parameters or fragments."
                .into(),
        );
    }
    let host = url
        .strip_prefix("https://")
        .and_then(|value| value.split_once('/'))
        .map(|(host, _)| host)
        .ok_or("Extension source must be a direct HTTPS archive URL.")?;
    let target = parse_https_target(url, &[host])?;
    let mut stream = connect_https(&target, tls_config()?)?;
    // No auth header, cookie jar, ambient proxy, redirect or install command.
    write!(stream, "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: GBPlus-Extension-Preview/1\r\nAccept: application/zip\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", target.path_and_query, target.host)
        .and_then(|()| stream.flush()).map_err(|e| e.to_string())?;
    let mut bounded = Deadline {
        stream,
        ends: std::time::Instant::now() + std::time::Duration::from_secs(90),
    };
    let head = read_http_head(&mut bounded)?;
    if head.status != 200 || head.chunked || head.encoded || head.content_length != Some(byte_len) {
        return Err(format!(
            "Archive response did not match its pinned length and unencoded HTTP 200 contract (status {}). Use its direct final URL.",
            head.status
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(byte_len).map_err(|e| e.to_string())?);
    let hash = copy_exact_body(
        &head.body_prefix,
        &mut bounded,
        &mut bytes,
        byte_len,
        &mut |_, _| {},
    )?;
    if hash != decode_sha256(sha256)? {
        return Err(
            "Extension archive SHA-256 does not match the admitted source; nothing was installed."
                .into(),
        );
    }
    Ok(bytes)
}

struct Deadline {
    stream: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    ends: std::time::Instant,
}
impl Read for Deadline {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .ends
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Extension archive deadline elapsed.",
                )
            })?;
        self.stream
            .sock
            .set_read_timeout(Some(remaining.min(std::time::Duration::from_secs(15))))?;
        self.stream.read(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unpinned_and_credential_bearing_sources_refuse_before_network_access() {
        for url in [
            "http://example.test/plugin.zip",
            "https://user:password@example.test/plugin.zip",
            "https://example.test/plugin.zip?token=secret",
            "https://example.test/a\r\nHost: other",
        ] {
            assert!(fetch(url, 32, &"a".repeat(64)).is_err());
        }
        assert!(fetch("https://example.test/plugin.zip", 0, &"a".repeat(64)).is_err());
        assert!(fetch("https://example.test/plugin.zip", 32, "unverified").is_err());
    }
}
