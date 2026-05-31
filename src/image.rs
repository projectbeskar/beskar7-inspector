//! Digest-pinned fetch of the target whole-disk OS image (contract §8.1).
//!
//! The target image (`beskar7.target`, a Kairos whole-disk raw) is a **distinct
//! trust domain** from the callback endpoints. It MAY be served over plain HTTP;
//! its integrity *and* authenticity come solely from `beskar7.target-digest`
//! (`sha256:<hex>`), delivered on the cmdline over the verified-TLS-derived
//! `/boot` channel. There is no signature — the digest is the only thing binding
//! the bytes to the operator.
//!
//! ## What this module does
//!   * [`Sha256Digest::parse`] — strict `^sha256:[0-9a-f]{64}$` parse of the
//!     cmdline value into 32 raw bytes.
//!   * [`validate_image_scheme`] — accept only `http://` / `https://`, rejecting
//!     `file://`, `unix://`, scheme-less paths, etc. (anti-SSRF, §8.1).
//!   * [`ImageFetcher::fetch_to`] — GET the image (redirects disabled) and
//!     [`stream_verify`] it straight to a caller-provided sink while hashing.
//!   * [`stream_verify`] — the pure, unit-testable core: stream reader→sink,
//!     hash incrementally, enforce the size bound, and compare the finalized
//!     digest with a full-length byte compare. **Returns `Ok` only on a match.**
//!
//! ## TLS posture (§8.1) — deliberately different from the callback client
//! The inspector's trust store holds **only** the cmdline-delivered callback CA
//! (see `src/client.rs`); it has **no** public webpki roots. It therefore cannot
//! and MUST NOT attempt to verify a TLS certificate for an arbitrary operator
//! image host. For an `https://` image, TLS is used for transport encryption
//! only: the [`NoCertVerify`] verifier performs the handshake-signature check but
//! skips trust-anchor and hostname validation. This is contract-sanctioned for
//! the image fetch **only** — the integrity gate is the SHA-256 digest, checked
//! after the whole stream is written — and is NEVER used on the callback path,
//! which pins the delivered CA with full verification.
//!
//! ## Verification model (§8.1): gate the *boot*, not the *write*
//! A whole-disk image is multi-GB, so it is streamed straight to the target sink
//! (the disk, in production) and never buffered in RAM. The digest is computed
//! incrementally over the same bytes. Only a verified-matching digest lets the
//! caller proceed to mount, inject user-data, and reboot; on any mismatch, short
//! read (which simply yields a non-matching digest), or size-limit breach the
//! caller MUST abort. A digest-failed write leaves the disk unbootable by design
//! (the host PXE-falls-back), which is safe because the image carries no secret.
//!
//! ## Secret hygiene (§9)
//! This module handles no secrets — the image is a public artifact, and the
//! digests are public. [`ImageError`] values are therefore safe to log in full,
//! including the expected/computed digests on a mismatch.

use std::fmt;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

/// Maximum image size the inspector will stream before aborting (§8.1 size
/// bound). A build default — v2 defines no `beskar7.*` cmdline override. A Kairos
/// whole-disk raw is a few GB; 16 GiB is a generous ceiling that still stops an
/// unbounded body from exhausting the target disk or stalling provisioning. A
/// real deployment SHOULD additionally cap this by the selected disk's capacity.
pub const DEFAULT_MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Streaming read/write buffer. Large enough for good throughput on a multi-GB
/// image without a meaningful memory footprint.
const READ_BUF_BYTES: usize = 1024 * 1024;

/// TCP connect timeout. Generous: a freshly-PXE-booted host may be on a slow or
/// congested provisioning network.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-read inactivity timeout. Bounds a stalled server without capping the total
/// download time of a legitimately large image (no overall call timeout is set).
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Errors from fetching/verifying the target image. These carry no secrets — the
/// image and its digest are public — so a logged `ImageError` is safe in full.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// `beskar7.target-digest` did not match `^sha256:[0-9a-f]{64}$`.
    #[error("beskar7.target-digest is not a valid sha256:<64-lowercase-hex> digest")]
    InvalidDigestFormat,
    /// `beskar7.target` used a scheme other than `http`/`https`.
    #[error("beskar7.target must be an http:// or https:// URL")]
    UnsupportedScheme,
    /// The image-fetch TLS client could not be initialized.
    #[error("initializing the image-fetch TLS client")]
    TlsSetup,
    /// The image server returned a non-success status (including an unfollowed
    /// 3xx, since redirects are disabled).
    #[error("image server returned HTTP {0}")]
    Http(u16),
    /// A transport-level failure (connect, timeout, TLS handshake, reset). The
    /// kind is a fixed description with no URL or header content.
    #[error("network transport error: {0}")]
    Transport(String),
    /// The image exceeded [`DEFAULT_MAX_IMAGE_BYTES`] (or the caller's bound).
    #[error("image exceeds the maximum size of {max_bytes} bytes")]
    TooLarge {
        /// The bound that was breached.
        max_bytes: u64,
    },
    /// Reading the image stream from the network failed mid-transfer.
    #[error("reading the image stream")]
    Read(#[source] std::io::Error),
    /// Writing the image to the target sink (the disk, in production) failed.
    #[error("writing the image to the target disk")]
    Write(#[source] std::io::Error),
    /// The fully-streamed image did not hash to `beskar7.target-digest`. Both
    /// digests are public and included to aid diagnosis. The caller MUST NOT
    /// mount, inject, or reboot.
    #[error("image digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch {
        /// The expected digest (from `beskar7.target-digest`).
        expected: String,
        /// The digest computed over the streamed bytes.
        computed: String,
    },
}

/// A parsed SHA-256 digest: the 32 raw bytes behind a `sha256:<hex>` string.
/// Comparison is byte-wise (and thus case-independent by construction), and
/// [`Display`](fmt::Display) renders the canonical lowercase `sha256:<hex>` form.
#[derive(Clone, PartialEq, Eq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Parse `sha256:<64-lowercase-hex>` (contract §8.1 / §5). Rejects a missing
    /// or wrong prefix, a length other than 64 hex chars, any non-`[0-9a-f]`
    /// character (uppercase included — the controller only ever renders the
    /// lowercase form the CRD pattern enforces), and anything else.
    pub fn parse(s: &str) -> Result<Self, ImageError> {
        let hex = s
            .strip_prefix("sha256:")
            .ok_or(ImageError::InvalidDigestFormat)?;
        if hex.len() != 64 {
            return Err(ImageError::InvalidDigestFormat);
        }
        let mut bytes = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(pair[0]).ok_or(ImageError::InvalidDigestFormat)?;
            let lo = hex_nibble(pair[1]).ok_or(ImageError::InvalidDigestFormat)?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Sha256Digest(bytes))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Map one lowercase-hex ASCII byte to its nibble value, or `None`. Uppercase is
/// intentionally rejected (the contract digest regex is `[0-9a-f]`).
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Accept only `http://` / `https://` (scheme compared case-insensitively).
/// Everything else — `file://`, `unix://`, a bare path, an empty string — is
/// rejected so a plain-HTTP MITM cannot steer the fetch at a local path or an
/// internal address (§8.1 anti-SSRF).
pub fn validate_image_scheme(url: &str) -> Result<(), ImageError> {
    match url.split_once("://") {
        Some((scheme, _))
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") =>
        {
            Ok(())
        }
        _ => Err(ImageError::UnsupportedScheme),
    }
}

/// A reusable image-fetch client. Built once; its TLS config uses [`NoCertVerify`]
/// (encryption-only, digest is the integrity anchor) and follows **no** redirects.
pub struct ImageFetcher {
    agent: ureq::Agent,
}

impl ImageFetcher {
    /// Build the fetcher. Fails only if the rustls config cannot be constructed.
    pub fn new() -> Result<Self, ImageError> {
        let agent = ureq::AgentBuilder::new()
            .tls_config(no_verify_tls_config()?)
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(READ_TIMEOUT)
            // No redirects: §8.1 forbids following a redirect to a non-http(s)
            // target, and safe redirect-following is deferred. An unfollowed 3xx
            // is surfaced as ImageError::Http below.
            .redirects(0)
            .build();
        Ok(Self { agent })
    }

    /// GET `url` and stream it to `sink`, verifying the fully-written bytes against
    /// `expected` and aborting past `max_bytes`. Returns the number of bytes
    /// written on a verified match. The write to `sink` happens before the digest
    /// gate — on a mismatch the sink holds the (unverified, non-secret) bytes and
    /// the caller MUST NOT proceed to boot them (§8.1).
    pub fn fetch_to<W: Write>(
        &self,
        url: &str,
        expected: &Sha256Digest,
        max_bytes: u64,
        sink: &mut W,
    ) -> Result<u64, ImageError> {
        validate_image_scheme(url)?;
        let resp = match self.agent.get(url).call() {
            Ok(resp) => {
                let code = resp.status();
                // Redirects are disabled, so a 3xx arrives here as Ok; treat any
                // non-2xx as an error rather than streaming a redirect body.
                if !(200..300).contains(&code) {
                    return Err(ImageError::Http(code));
                }
                resp
            }
            Err(ureq::Error::Status(code, _resp)) => return Err(ImageError::Http(code)),
            Err(ureq::Error::Transport(t)) => {
                return Err(ImageError::Transport(t.kind().to_string()))
            }
        };
        stream_verify(resp.into_reader(), expected, max_bytes, sink)
    }
}

/// Stream `reader` to `sink`, hashing as we go, aborting if more than `max_bytes`
/// arrive, and finally comparing the SHA-256 to `expected` with a full-length
/// byte compare. Pure and transport-agnostic — the network, the disk, and the
/// hash are all injected — so the size bound and the digest gate are unit-tested
/// without a server or a real block device.
///
/// Returns the byte count on a verified match; otherwise an [`ImageError`]. On
/// any error the caller MUST treat the sink's contents as unusable (§8.1).
pub fn stream_verify<R: Read, W: Write>(
    reader: R,
    expected: &Sha256Digest,
    max_bytes: u64,
    sink: &mut W,
) -> Result<u64, ImageError> {
    // Backstop the byte accounting: never pull more than one byte past the bound
    // from the underlying reader, even if the loop's own check had a bug.
    let mut limited = reader.take(max_bytes.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_BUF_BYTES];
    let mut total: u64 = 0;

    loop {
        let n = limited.read(&mut buf).map_err(ImageError::Read)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max_bytes {
            return Err(ImageError::TooLarge { max_bytes });
        }
        hasher.update(&buf[..n]);
        sink.write_all(&buf[..n]).map_err(ImageError::Write)?;
    }
    sink.flush().map_err(ImageError::Write)?;

    let computed = Sha256Digest(hasher.finalize().into());
    if computed != *expected {
        return Err(ImageError::DigestMismatch {
            expected: expected.to_string(),
            computed: computed.to_string(),
        });
    }
    Ok(total)
}

/// Build a rustls config for the image fetch that performs the handshake-signature
/// check but skips trust-anchor/hostname validation (§8.1). Confined to this
/// module; never used on the callback path.
fn no_verify_tls_config() -> Result<Arc<ClientConfig>, ImageError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(NoCertVerify {
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ImageError::TlsSetup)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A `ServerCertVerifier` that validates the TLS handshake signature (proving the
/// peer holds the private key for the certificate it presented) but performs **no**
/// trust-anchor or hostname validation.
///
/// This exists because the inspector ships no webpki roots and MUST NOT attempt to
/// verify an arbitrary operator image host (§8.1). For the image fetch, TLS is
/// transport encryption only; the SHA-256 digest is the integrity/authenticity
/// anchor. It is intentionally NEVER constructed for the callback client, whose
/// `RootCertStore` pins the cmdline-delivered CA with full verification.
#[derive(Debug)]
struct NoCertVerify {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // §8.1: no trust anchors, so no chain/name validation is possible or
        // permitted here. Integrity is enforced later by the digest gate.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of the empty input — the canonical lowercase digest literal reused
    /// across the format tests.
    const EMPTY_DIGEST: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn digest_of(data: &[u8]) -> Sha256Digest {
        let mut h = Sha256::new();
        h.update(data);
        Sha256Digest(h.finalize().into())
    }

    #[test]
    fn parse_accepts_valid_lowercase_digest_and_round_trips() {
        let d = Sha256Digest::parse(EMPTY_DIGEST).expect("valid");
        assert_eq!(d.to_string(), EMPTY_DIGEST);
    }

    #[test]
    fn parse_rejects_missing_or_wrong_prefix() {
        // Bare hex with no `sha256:`.
        assert!(matches!(
            Sha256Digest::parse(&EMPTY_DIGEST[7..]),
            Err(ImageError::InvalidDigestFormat)
        ));
        // A different (unsupported) algorithm prefix.
        let sha512ish = format!("sha512:{}", &EMPTY_DIGEST[7..]);
        assert!(matches!(
            Sha256Digest::parse(&sha512ish),
            Err(ImageError::InvalidDigestFormat)
        ));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let short = format!("sha256:{}", "a".repeat(63));
        let long = format!("sha256:{}", "a".repeat(65));
        assert!(matches!(
            Sha256Digest::parse(&short),
            Err(ImageError::InvalidDigestFormat)
        ));
        assert!(matches!(
            Sha256Digest::parse(&long),
            Err(ImageError::InvalidDigestFormat)
        ));
    }

    #[test]
    fn parse_rejects_non_hex_character() {
        // 'g' is outside [0-9a-f]; 63 valid chars + one invalid keeps length 64.
        let bad = format!("sha256:g{}", "a".repeat(63));
        assert!(matches!(
            Sha256Digest::parse(&bad),
            Err(ImageError::InvalidDigestFormat)
        ));
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        // The CRD pattern is lowercase-only; uppercase is a malformed digest.
        let upper = format!("sha256:{}", "A".repeat(64));
        assert!(matches!(
            Sha256Digest::parse(&upper),
            Err(ImageError::InvalidDigestFormat)
        ));
    }

    #[test]
    fn scheme_accepts_http_and_https_rejects_others() {
        assert!(validate_image_scheme("http://images.example.com/x.raw").is_ok());
        assert!(validate_image_scheme("https://images.example.com/x.raw").is_ok());
        // Case-insensitive scheme is still accepted.
        assert!(validate_image_scheme("HTTPS://images.example.com/x.raw").is_ok());
        for bad in [
            "file:///etc/passwd",
            "unix:///var/run/x.sock",
            "ftp://images.example.com/x.raw",
            "/dev/sda",
            "images.example.com/x.raw",
            "",
        ] {
            assert!(
                matches!(
                    validate_image_scheme(bad),
                    Err(ImageError::UnsupportedScheme)
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn stream_verify_matches_and_returns_length() {
        let data = b"whole-disk image bytes for the happy path";
        let expected = digest_of(data);
        let mut sink = Vec::new();
        let n = stream_verify(&data[..], &expected, 1024, &mut sink).expect("match");
        assert_eq!(n, data.len() as u64);
        assert_eq!(sink, data);
    }

    #[test]
    fn stream_verify_reports_mismatch_but_still_wrote_the_bytes() {
        // The write precedes the gate (§8.1): the sink fills, but the boot
        // decision is refused.
        let actual = b"the bytes actually served";
        let expected = digest_of(b"a different, expected image");
        let mut sink = Vec::new();
        let err = stream_verify(&actual[..], &expected, 1024, &mut sink).unwrap_err();
        match err {
            ImageError::DigestMismatch {
                expected: e,
                computed: c,
            } => {
                assert_eq!(e, digest_of(b"a different, expected image").to_string());
                assert_eq!(c, digest_of(actual).to_string());
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        assert_eq!(sink, actual, "bytes are written before the gate");
    }

    #[test]
    fn stream_verify_aborts_over_the_size_bound() {
        let data = vec![0xABu8; 100];
        let expected = digest_of(&data);
        let mut sink = Vec::new();
        let err = stream_verify(&data[..], &expected, 50, &mut sink).unwrap_err();
        assert!(matches!(err, ImageError::TooLarge { max_bytes: 50 }));
    }

    #[test]
    fn stream_verify_accepts_a_body_exactly_at_the_bound() {
        let data = vec![0x5Au8; 64];
        let expected = digest_of(&data);
        let mut sink = Vec::new();
        let n = stream_verify(&data[..], &expected, 64, &mut sink).expect("at-limit is ok");
        assert_eq!(n, 64);
        assert_eq!(sink.len(), 64);
    }

    #[test]
    fn stream_verify_handles_empty_body_with_empty_digest() {
        let expected = Sha256Digest::parse(EMPTY_DIGEST).expect("valid");
        let mut sink = Vec::new();
        let n = stream_verify(&b""[..], &expected, 1024, &mut sink).expect("empty matches");
        assert_eq!(n, 0);
        assert!(sink.is_empty());
    }

    #[test]
    fn fetcher_builds() {
        assert!(ImageFetcher::new().is_ok());
    }

    #[test]
    fn no_verify_advertises_signature_schemes() {
        let verifier = NoCertVerify {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        assert!(
            !verifier.supported_verify_schemes().is_empty(),
            "the verifier must advertise schemes or rustls rejects the handshake"
        );
    }
}
