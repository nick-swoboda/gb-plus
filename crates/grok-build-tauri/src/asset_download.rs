//! Fixed-identity HTTPS runtime assets stored beneath Application Support.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek as _, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::BuilderVerifierExt as _;
use sha2::{Digest as _, Sha256};

const TLS_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 5;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) mod extension_archive;

/// One immutable downloadable runtime input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AssetSpec {
    pub(crate) id: &'static str,
    pub(crate) filename: &'static str,
    pub(crate) url: &'static str,
    pub(crate) byte_len: u64,
    pub(crate) sha256: &'static str,
    pub(crate) allowed_hosts: &'static [&'static str],
}

/// Result of ensuring one runtime input exists and verifies.
#[derive(Clone, Debug)]
pub(crate) struct InstalledAsset {
    pub(crate) downloaded: bool,
}

/// Owner-only fixed-asset store.
#[derive(Clone, Debug)]
pub(crate) struct AssetManager {
    root: PathBuf,
}

impl AssetManager {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn verified_path(&self, spec: AssetSpec) -> Result<Option<PathBuf>, String> {
        let path = self.asset_path(spec)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                verify_asset_file(&path, spec)?;
                Ok(Some(path))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Cannot inspect the {} asset: {error}", spec.id)),
        }
    }

    /// Opens and verifies the exact descriptor a runtime consumer will use.
    ///
    /// Verification through a path followed by a second open would leave a
    /// path-replacement window. This keeps the verified file description open,
    /// checks that it still identifies the path we inspected, and rewinds it
    /// before returning it to the consumer.
    pub(crate) fn open_verified(&self, spec: AssetSpec) -> Result<Option<File>, String> {
        let path = self.asset_path(spec)?;
        match fs::symlink_metadata(&path) {
            Ok(path_metadata) => open_and_verify_asset(&path, &path_metadata, spec).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Cannot inspect the {} asset: {error}", spec.id)),
        }
    }

    pub(crate) fn install<F>(
        &self,
        spec: AssetSpec,
        mut progress: F,
    ) -> Result<InstalledAsset, String>
    where
        F: FnMut(u64, u64),
    {
        validate_spec(spec)?;
        ensure_private_directory(&self.root)?;
        let final_path = self.asset_path(spec)?;
        if let Ok(Some(_)) = self.verified_path(spec) {
            return Ok(InstalledAsset { downloaded: false });
        }

        let temp_path = self.root.join(format!(
            ".{}.download-{}-{}",
            spec.filename,
            std::process::id(),
            monotonic_nonce()
        ));
        let result = (|| {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp_path)
                .map_err(|error| {
                    format!("Cannot create the private {} download: {error}", spec.id)
                })?;
            let digest = download_https(spec, &mut output, &mut progress)?;
            output
                .sync_all()
                .map_err(|error| format!("Cannot sync the {} download: {error}", spec.id))?;
            let expected = decode_sha256(spec.sha256)?;
            if digest.as_slice() != expected {
                return Err(format!(
                    "The {} download failed SHA-256 verification; the feature remains unavailable.",
                    spec.id
                ));
            }
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("Cannot secure the {} download: {error}", spec.id))?;
            fs::rename(&temp_path, &final_path).map_err(|error| {
                format!("Cannot atomically promote the {} asset: {error}", spec.id)
            })?;
            sync_directory(&self.root)?;
            verify_asset_file(&final_path, spec)?;
            Ok(InstalledAsset { downloaded: true })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn asset_path(&self, spec: AssetSpec) -> Result<PathBuf, String> {
        validate_spec(spec)?;
        Ok(self.root.join(spec.filename))
    }
}

#[derive(Debug)]
struct HttpsTarget {
    host: String,
    path_and_query: String,
}

#[derive(Debug)]
struct HttpHead {
    status: u16,
    content_length: Option<u64>,
    location: Option<String>,
    chunked: bool,
    encoded: bool,
    body_prefix: Vec<u8>,
}

fn validate_spec(spec: AssetSpec) -> Result<(), String> {
    if spec.id.is_empty()
        || spec.id.len() > 64
        || !spec
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("Runtime asset identity is invalid.".into());
    }
    if spec.filename.is_empty()
        || spec.filename.len() > 128
        || !spec
            .filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || spec.filename == "."
        || spec.filename == ".."
    {
        return Err("Runtime asset filename is invalid.".into());
    }
    if spec.byte_len == 0 || spec.byte_len > 2 * 1024 * 1024 * 1024 {
        return Err("Runtime asset byte bound is invalid.".into());
    }
    let _ = decode_sha256(spec.sha256)?;
    let _ = parse_https_target(spec.url, spec.allowed_hosts)?;
    Ok(())
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create the runtime asset directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect the runtime asset directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Runtime asset storage refused a non-directory or symlink root.".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("Cannot secure the runtime asset directory: {error}"))
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("Cannot sync the runtime asset directory: {error}"))
}

fn verify_asset_file(path: &Path, spec: AssetSpec) -> Result<(), String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect the {} asset: {error}", spec.id))?;
    let _verified = open_and_verify_asset(path, &path_metadata, spec)?;
    Ok(())
}

fn open_and_verify_asset(
    path: &Path,
    path_metadata: &fs::Metadata,
    spec: AssetSpec,
) -> Result<File, String> {
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(format!("The {} asset is not a regular file.", spec.id));
    }
    if path_metadata.len() != spec.byte_len {
        return Err(format!(
            "The {} asset has the wrong byte length; reinstall it before use.",
            spec.id
        ));
    }
    if path_metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "The {} asset permissions are not owner-only.",
            spec.id
        ));
    }
    let mut file = File::open(path).map_err(|error| {
        format!(
            "Cannot open the {} asset for verification: {error}",
            spec.id
        )
    })?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("Cannot inspect the open {} asset: {error}", spec.id))?;
    if !opened_metadata.is_file()
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
        || opened_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "The {} asset changed identity or permissions while it was opened.",
            spec.id
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash the {} asset: {error}", spec.id))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if digest.finalize().as_slice() != decode_sha256(spec.sha256)? {
        return Err(format!(
            "The {} asset failed SHA-256 verification; it will not be loaded.",
            spec.id
        ));
    }
    let final_metadata = file
        .metadata()
        .map_err(|error| format!("Cannot re-inspect the open {} asset: {error}", spec.id))?;
    if final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
        || final_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "The {} asset changed while it was being verified.",
            spec.id
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Cannot rewind the verified {} asset: {error}", spec.id))?;
    Ok(file)
}

fn download_https<F>(
    spec: AssetSpec,
    output: &mut File,
    progress: &mut F,
) -> Result<[u8; 32], String>
where
    F: FnMut(u64, u64),
{
    let tls = tls_config()?;
    let mut target = parse_https_target(spec.url, spec.allowed_hosts)?;
    for redirect_count in 0..=MAX_REDIRECTS {
        let mut stream = connect_https(&target, Arc::clone(&tls))?;
        write!(
            stream,
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Grok-Build-Plus/0.2\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target.path_and_query, target.host
        )
        .and_then(|()| stream.flush())
        .map_err(|error| format!("Runtime asset HTTPS request failed: {error}"))?;
        let head = read_http_head(&mut stream)?;
        if matches!(head.status, 301 | 302 | 303 | 307 | 308) {
            if redirect_count == MAX_REDIRECTS {
                return Err("Runtime asset HTTPS redirect limit was exceeded.".into());
            }
            let location = head
                .location
                .ok_or_else(|| "Runtime asset redirect omitted Location.".to_owned())?;
            target = parse_https_target(&location, spec.allowed_hosts)?;
            continue;
        }
        if head.status != 200 {
            return Err(format!(
                "Runtime asset server returned HTTP {}; no asset was promoted.",
                head.status
            ));
        }
        if head.chunked || head.encoded {
            return Err(
                "Runtime asset response used an unadmitted transfer/content encoding.".into(),
            );
        }
        if head.content_length != Some(spec.byte_len) {
            return Err("Runtime asset server did not bind the exact admitted byte length.".into());
        }
        let digest = copy_exact_body(
            &head.body_prefix,
            &mut stream,
            output,
            spec.byte_len,
            progress,
        )?;
        return Ok(digest);
    }
    Err("Runtime asset download did not produce a terminal response.".into())
}

fn tls_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("Runtime asset TLS versions failed: {error}"))?
        .with_platform_verifier()
        .map_err(|error| format!("Runtime asset platform verifier unavailable: {error}"))?
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn connect_https(
    target: &HttpsTarget,
    config: Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let addresses = (target.host.as_str(), TLS_PORT)
        .to_socket_addrs()
        .map_err(|error| format!("Runtime asset DNS failed: {error}"))?;
    let mut last_error = None;
    let mut socket = None;
    for address in addresses.take(8) {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(candidate) => {
                socket = Some(candidate);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let socket = socket.ok_or_else(|| {
        last_error.map_or_else(
            || "Runtime asset DNS returned no addresses.".to_owned(),
            |error| format!("Runtime asset connection failed: {error}"),
        )
    })?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("Runtime asset socket timeout setup failed: {error}"))?;
    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|_| "Runtime asset TLS hostname is invalid.".to_owned())?;
    let connection = ClientConnection::new(config, server_name)
        .map_err(|error| format!("Runtime asset TLS setup failed: {error}"))?;
    Ok(StreamOwned::new(connection, socket))
}

fn parse_https_target(url: &str, allowed_hosts: &[&str]) -> Result<HttpsTarget, String> {
    if url.len() > 16 * 1024 || url.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err("Runtime asset URL is invalid.".into());
    }
    let remainder = url
        .strip_prefix("https://")
        .ok_or_else(|| "Runtime asset URL must use HTTPS.".to_owned())?;
    let (authority, tail) = remainder
        .split_once('/')
        .ok_or_else(|| "Runtime asset URL is missing a path.".to_owned())?;
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains(':')
        || !authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("Runtime asset HTTPS authority is invalid.".into());
    }
    let host = authority.to_ascii_lowercase();
    if !allowed_asset_host(&host, allowed_hosts) {
        return Err("Runtime asset redirect left the fixed HTTPS host allowlist.".into());
    }
    let path_and_query = format!("/{tail}");
    if path_and_query.contains('#') || path_and_query.len() > 14 * 1024 {
        return Err("Runtime asset HTTPS path is invalid.".into());
    }
    Ok(HttpsTarget {
        host,
        path_and_query,
    })
}

fn allowed_asset_host(host: &str, allowed_hosts: &[&str]) -> bool {
    !allowed_hosts.is_empty()
        && allowed_hosts.iter().any(|allowed| {
            host == *allowed
                || allowed
                    .strip_prefix("*.")
                    .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
        })
}

fn read_http_head(stream: &mut impl Read) -> Result<HttpHead, String> {
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) = find_subslice(&bytes, b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err("Runtime asset HTTP headers exceeded the fixed bound.".into());
        }
        let mut buffer = [0_u8; 4096];
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("Runtime asset HTTP header read failed: {error}"))?;
        if count == 0 {
            return Err("Runtime asset HTTP response ended before its headers.".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let header_text = std::str::from_utf8(&bytes[..header_end - 4])
        .map_err(|_| "Runtime asset HTTP headers were not UTF-8/ASCII.".to_owned())?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "Runtime asset HTTP status line is missing.".to_owned())?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "Runtime asset HTTP status is malformed.".to_owned())?;
    if !matches!(version, Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err("Runtime asset HTTP version is unsupported.".into());
    }
    let mut content_length = None;
    let mut location = None;
    let mut chunked = false;
    let mut encoded = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "Runtime asset HTTP header is malformed.".to_owned())?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| "Runtime asset Content-Length is malformed.".to_owned())?;
                if content_length
                    .replace(parsed)
                    .is_some_and(|old| old != parsed)
                {
                    return Err(
                        "Runtime asset response has conflicting Content-Length values.".into(),
                    );
                }
            }
            "location" => {
                if location.replace(value.to_owned()).is_some() {
                    return Err("Runtime asset response has duplicate Location headers.".into());
                }
            }
            "transfer-encoding" if !value.eq_ignore_ascii_case("identity") => chunked = true,
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => encoded = true,
            _ => {}
        }
    }
    Ok(HttpHead {
        status,
        content_length,
        location,
        chunked,
        encoded,
        body_prefix: bytes[header_end..].to_vec(),
    })
}

fn copy_exact_body<F>(
    prefix: &[u8],
    input: &mut impl Read,
    output: &mut impl Write,
    expected: u64,
    progress: &mut F,
) -> Result<[u8; 32], String>
where
    F: FnMut(u64, u64),
{
    if u64::try_from(prefix.len()).map_err(|_| "Runtime asset body overflow.".to_owned())?
        > expected
    {
        return Err("Runtime asset body exceeded its admitted byte length.".into());
    }
    let mut digest = Sha256::new();
    output
        .write_all(prefix)
        .map_err(|error| format!("Runtime asset write failed: {error}"))?;
    digest.update(prefix);
    let mut written =
        u64::try_from(prefix.len()).map_err(|_| "Runtime asset body overflow.".to_owned())?;
    progress(written, expected);
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    while written < expected {
        let remaining = usize::try_from((expected - written).min(COPY_BUFFER_BYTES as u64))
            .map_err(|_| "Runtime asset byte bound overflow.".to_owned())?;
        let count = input
            .read(&mut buffer[..remaining])
            .map_err(|error| format!("Runtime asset body read failed: {error}"))?;
        if count == 0 {
            return Err("Runtime asset body ended before its admitted byte length.".into());
        }
        output
            .write_all(&buffer[..count])
            .map_err(|error| format!("Runtime asset write failed: {error}"))?;
        digest.update(&buffer[..count]);
        written = written
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| "Runtime asset byte count overflow.".to_owned())?,
            )
            .ok_or_else(|| "Runtime asset byte count overflow.".to_owned())?;
        progress(written, expected);
    }
    Ok(digest.finalize().into())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Runtime asset SHA-256 identity is invalid.".into());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("Runtime asset SHA-256 identity is invalid.".into()),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn monotonic_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SPEC: AssetSpec = AssetSpec {
        id: "test-asset",
        filename: "test.bin",
        url: "https://huggingface.co/example/revision/test.bin",
        byte_len: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        allowed_hosts: &["huggingface.co", "*.hf.co"],
    };

    #[test]
    fn fixed_hosts_and_urls_fail_closed() {
        assert!(parse_https_target(TEST_SPEC.url, TEST_SPEC.allowed_hosts).is_ok());
        assert!(
            parse_https_target(
                "https://us.aws.cdn.hf.co/path?token=opaque",
                TEST_SPEC.allowed_hosts
            )
            .is_ok()
        );
        assert!(parse_https_target("http://huggingface.co/path", TEST_SPEC.allowed_hosts).is_err());
        assert!(
            parse_https_target(
                "https://huggingface.co.evil.test/path",
                TEST_SPEC.allowed_hosts
            )
            .is_err()
        );
        assert!(
            parse_https_target("https://user@huggingface.co/path", TEST_SPEC.allowed_hosts)
                .is_err()
        );
        assert!(
            parse_https_target("https://huggingface.co:444/path", TEST_SPEC.allowed_hosts).is_err()
        );
        assert!(
            parse_https_target(
                "https://storage.googleapis.com/fixed/object.zip",
                &["storage.googleapis.com"]
            )
            .is_ok()
        );
        assert!(
            parse_https_target(
                "https://storage.googleapis.com.evil.test/object.zip",
                &["storage.googleapis.com"]
            )
            .is_err()
        );
    }

    #[test]
    fn response_parser_binds_length_and_encoding() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: identity\r\n\r\nabc";
        let head = read_http_head(&mut response.as_slice()).expect("parse response");
        assert_eq!(head.status, 200);
        assert_eq!(head.content_length, Some(3));
        assert_eq!(head.body_prefix, b"abc");
        assert!(!head.chunked);
        assert!(!head.encoded);

        let conflicting = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n";
        assert!(read_http_head(&mut conflicting.as_slice()).is_err());
    }

    #[test]
    fn exact_body_refuses_short_or_long_prefix() {
        let mut output = Vec::new();
        let digest = copy_exact_body(b"a", &mut b"bc".as_slice(), &mut output, 3, &mut |_, _| {})
            .expect("copy exact body");
        assert_eq!(output, b"abc");
        assert_eq!(
            digest,
            decode_sha256(TEST_SPEC.sha256).expect("decode hash")
        );
        assert!(
            copy_exact_body(b"abcd", &mut &b""[..], &mut Vec::new(), 3, &mut |_, _| {}).is_err()
        );
        assert!(copy_exact_body(b"a", &mut &b""[..], &mut Vec::new(), 3, &mut |_, _| {}).is_err());
    }

    #[test]
    fn local_verification_rejects_corruption_and_open_permissions() {
        let root = std::env::temp_dir().join(format!(
            "grok-asset-test-{}-{}",
            std::process::id(),
            monotonic_nonce()
        ));
        ensure_private_directory(&root).expect("private root");
        let path = root.join(TEST_SPEC.filename);
        fs::write(&path, b"abc").expect("fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        verify_asset_file(&path, TEST_SPEC).expect("verified fixture");
        fs::write(&path, b"abd").expect("corrupt fixture");
        assert!(verify_asset_file(&path, TEST_SPEC).is_err());
        fs::write(&path, b"abc").expect("restore fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("open permissions");
        assert!(verify_asset_file(&path, TEST_SPEC).is_err());
        fs::remove_dir_all(&root).expect("cleanup fixture root");
    }
}
