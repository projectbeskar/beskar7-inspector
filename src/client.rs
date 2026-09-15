//! Verified-TLS callback client: submit the inspection report and fetch the CAPI
//! bootstrap user-data (contract §4.2/§4.3/§8/§9).
//!
//! Three requests, all `Authorization: Bearer <token>` over TLS verified against
//! the CA delivered on the cmdline (`beskar7.ca`):
//!   * `POST {api}/api/v1/inspection/{ns}/{host}` — the §6 report. Success is
//!     **202 Accepted** (the controller writes status asynchronously); the client
//!     treats any 2xx as success and retries only *transient* failures.
//!   * `GET {api}/api/v1/bootstrap/{ns}/{host}` — raw CAPI user-data bytes (which
//!     **may contain cluster join secrets**, contract §4.3/§9).
//!   * `POST {api}/api/v1/provisioned/{ns}/{host}` — the provisioning-complete
//!     callback (D-015), fired after the verified whole-disk write + OEM inject
//!     and before the reboot, so the controller learns the deploy outcome. Body is
//!     the fixed advisory `{"status":"provisioned"}`; success is **202 Accepted**,
//!     same retry policy as the inspection POST.
//!   * `POST {api}/api/v1/provision-failed/{ns}/{host}` — the provision-failed
//!     callback (D-015 v4.1), fired on a deploy-step failure (image fetch/digest/
//!     whole-disk write/partition re-read/`COS_OEM` inject) *after* the host has
//!     moved to Deploying, so the controller fails the machine promptly instead of
//!     waiting out its deployment timeout. Body is a small advisory
//!     `{"reason":"<short deploy-step reason>"}` carrying **no secret** (never the
//!     token, nonce, or join data); success is **202 Accepted**, same retry policy
//!     as the inspection POST.
//!
//! ## TLS posture (§8)
//! The root store holds *only* the delivered CA — [`RootCertStore::empty`] plus
//! that one cert, never the public webpki roots — and there is deliberately no
//! insecure-skip-verify path: a MITM on these requests is a cluster compromise.
//! The crypto provider is pinned to `ring` (see `Cargo.toml`).
//!
//! ## Secret hygiene (§9)
//! This module never logs. The bearer token lives only in the `Authorization`
//! header it builds at the point of use, and the bootstrap bytes are returned to
//! the caller without ever being formatted. Error values carry only status codes
//! and transport-error *kinds* (never URLs, headers, or bodies), so a logged
//! `ClientError` cannot leak the token or the user-data.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;

use crate::cmdline::BootParams;
use crate::report::InspectionReport;
use crate::secret::Secret;

/// How many times each request is attempted before giving up (1 initial try plus
/// retries on transient failures).
const MAX_ATTEMPTS: u32 = 5;
/// First retry backoff; doubles each attempt up to [`BACKOFF_CAP`].
const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// Ceiling on the per-retry backoff so a long run of transient failures does not
/// stretch each wait unboundedly.
const BACKOFF_CAP: Duration = Duration::from_secs(8);
/// TCP connect timeout for each attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Overall per-request timeout for each attempt (connect + transfer).
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Defensive cap on the bootstrap response body. CAPI user-data (cloud-init /
/// Ignition) is far smaller than this; a larger response is treated as an error
/// rather than buffered, so a buggy or hostile server cannot exhaust memory.
const MAX_BOOTSTRAP_BYTES: u64 = 4 * 1024 * 1024;
/// The fixed, advisory body of the provisioning-complete callback (D-015). The
/// server treats it as advisory — the path/host carry the identity — so it is a
/// small constant and carries nothing secret.
const PROVISIONED_BODY: &[u8] = br#"{"status":"provisioned"}"#;

/// Errors from the callback client. Variants deliberately carry no URLs, headers,
/// or bodies — only status codes and transport-error kinds — so logging a
/// `ClientError` cannot leak the bearer token or the bootstrap user-data (§9).
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// `beskar7.ca` was not valid base64.
    #[error("beskar7.ca is not valid base64")]
    CaDecode,
    /// `beskar7.ca` decoded but contained no PEM certificate.
    #[error("beskar7.ca contained no certificate")]
    CaEmpty,
    /// A certificate in `beskar7.ca` could not be parsed / added to the trust store.
    #[error("beskar7.ca is not a valid PEM certificate")]
    CaInvalid,
    /// The callback returned a non-success, non-retryable HTTP status.
    #[error("callback returned HTTP {0}")]
    Http(u16),
    /// A transport-level failure (connect, timeout, TLS handshake, reset). The
    /// kind is a fixed description with no URL or header content.
    #[error("network transport error: {0}")]
    Transport(String),
    /// The response body could not be read.
    #[error("reading response body")]
    Body,
    /// The bootstrap body exceeded [`MAX_BOOTSTRAP_BYTES`].
    #[error("bootstrap user-data exceeds the size limit")]
    BootstrapTooLarge,
    /// The report could not be serialized to JSON.
    #[error("serializing the inspection report")]
    Serialize,
    /// All attempts were exhausted; carries the last transient error seen.
    #[error("exhausted retries; last error: {0}")]
    RetriesExhausted(Box<ClientError>),
}

/// A verified-TLS client bound to one host's callback endpoints and bearer token.
pub struct CallbackClient {
    agent: ureq::Agent,
    inspection_url: String,
    bootstrap_url: String,
    provisioned_url: String,
    provision_failed_url: String,
    token: Secret,
}

impl CallbackClient {
    /// Build a client for the host described by `params`, trusting only the CA in
    /// `params.ca`. Fails if the CA cannot be decoded/parsed or TLS setup fails.
    pub fn new(params: &BootParams) -> Result<Self, ClientError> {
        let tls = tls_config(&params.ca)?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(CALL_TIMEOUT))
            // No redirects: the callback never redirects, and following a 3xx
            // could be steered cross-scheme/cross-host by a MITM.
            .max_redirects(0)
            // Hand every response back as Ok so classify_status is the single
            // place that decides retryable vs fatal. Without this ureq turns
            // non-2xx into Err(StatusCode) and the same decision would be split
            // across two match arms.
            .http_status_as_error(false)
            .build()
            .into();
        Ok(Self {
            agent,
            inspection_url: inspection_url(&params.api, &params.namespace, &params.host),
            bootstrap_url: bootstrap_url(&params.api, &params.namespace, &params.host),
            provisioned_url: provisioned_url(&params.api, &params.namespace, &params.host),
            provision_failed_url: provision_failed_url(
                &params.api,
                &params.namespace,
                &params.host,
            ),
            token: params.token.clone(),
        })
    }

    /// POST the report; treat 202 (any 2xx) as success, retry transient failures
    /// with backoff (§4.2/§9).
    pub fn submit_report(&self, report: &InspectionReport) -> Result<(), ClientError> {
        let body = serde_json::to_vec(report).map_err(|_| ClientError::Serialize)?;
        let auth = self.bearer();
        run_with_retries(MAX_ATTEMPTS, sleep, |_| {
            let result = self
                .agent
                .post(&self.inspection_url)
                .header("Authorization", &auth)
                .header("Content-Type", "application/json")
                .send(&body[..]);
            match classify_status(result) {
                Ok(_resp) => Attempt::Done(()),
                Err(verdict) => verdict.into_attempt(),
            }
        })
    }

    /// GET the CAPI bootstrap user-data with the same bearer (§4.3). The returned
    /// bytes may contain cluster join secrets and MUST NOT be logged (§9).
    pub fn fetch_bootstrap(&self) -> Result<Vec<u8>, ClientError> {
        let auth = self.bearer();
        run_with_retries(MAX_ATTEMPTS, sleep, |_| {
            let result = self
                .agent
                .get(&self.bootstrap_url)
                .header("Authorization", &auth)
                .call();
            match classify_status(result) {
                Ok(resp) => match read_capped(resp, MAX_BOOTSTRAP_BYTES) {
                    Ok(bytes) => Attempt::Done(bytes),
                    // A mid-stream read failure is transient; an over-limit body
                    // is a fatal protocol violation.
                    Err(ClientError::BootstrapTooLarge) => {
                        Attempt::Fatal(ClientError::BootstrapTooLarge)
                    }
                    Err(e) => Attempt::Retry(e),
                },
                Err(verdict) => verdict.into_attempt(),
            }
        })
    }

    /// POST the provisioning-complete callback after the verified deploy and
    /// before the reboot (D-015), so the controller learns the host provisioned.
    /// Mirrors [`submit_report`](Self::submit_report): the fixed advisory
    /// [`PROVISIONED_BODY`], the same bearer, 202 (any 2xx) treated as success,
    /// transient transport/5xx failures retried with backoff.
    pub fn provisioned(&self) -> Result<(), ClientError> {
        let auth = self.bearer();
        run_with_retries(MAX_ATTEMPTS, sleep, |_| {
            let result = self
                .agent
                .post(&self.provisioned_url)
                .header("Authorization", &auth)
                .header("Content-Type", "application/json")
                .send(PROVISIONED_BODY);
            match classify_status(result) {
                Ok(_resp) => Attempt::Done(()),
                Err(verdict) => verdict.into_attempt(),
            }
        })
    }

    /// POST the provision-failed callback when a deploy step fails after the host
    /// has moved to Deploying (D-015 v4.1), so the controller fails the machine
    /// promptly rather than waiting out its deployment timeout. Mirrors
    /// [`provisioned`](Self::provisioned): the same bearer, 202 (any 2xx) treated as
    /// success, transient transport/5xx failures retried with backoff. The body is a
    /// small advisory `{"reason":<reason>}` — `reason` is a short, secret-free
    /// deploy-step description that the caller controls; it is JSON-escaped via
    /// [`provision_failed_body`] and **must never** carry the token, nonce, or join
    /// data (§9).
    pub fn provision_failed(&self, reason: &str) -> Result<(), ClientError> {
        let body = provision_failed_body(reason)?;
        let auth = self.bearer();
        run_with_retries(MAX_ATTEMPTS, sleep, |_| {
            let result = self
                .agent
                .post(&self.provision_failed_url)
                .header("Authorization", &auth)
                .header("Content-Type", "application/json")
                .send(&body[..]);
            match classify_status(result) {
                Ok(_resp) => Attempt::Done(()),
                Err(verdict) => verdict.into_attempt(),
            }
        })
    }

    /// The `Authorization` header value. Built only here, at the point of use —
    /// never logged or stored expanded (§9).
    fn bearer(&self) -> String {
        format!("Bearer {}", self.token.expose())
    }
}

/// Serialize the provision-failed body `{"reason":<reason>}`, JSON-escaping
/// `reason` via serde so a quote, backslash, or control char in the reason cannot
/// break the JSON or smuggle extra fields. `reason` is short and caller-controlled
/// (a deploy-step description) and carries no secret (§9).
fn provision_failed_body(reason: &str) -> Result<Vec<u8>, ClientError> {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        reason: &'a str,
    }
    serde_json::to_vec(&Body { reason }).map_err(|_| ClientError::Serialize)
}

/// A non-success classification of one HTTP attempt: either retry or stop. The
/// success case is carried by the `Ok(ureq::Response)` side of
/// [`classify_status`]'s result, so this enum stays small (no large `Response`
/// variant) and maps cleanly onto [`Attempt`] via [`Verdict::into_attempt`].
enum Verdict {
    /// A transient failure worth retrying.
    Retry(ClientError),
    /// A terminal failure; stop now.
    Fatal(ClientError),
}

impl Verdict {
    /// Lift a verdict into an [`Attempt`] of any success type, so a request
    /// closure can fold the error path uniformly regardless of its `T`.
    fn into_attempt<T>(self) -> Attempt<T> {
        match self {
            Verdict::Retry(e) => Attempt::Retry(e),
            Verdict::Fatal(e) => Attempt::Fatal(e),
        }
    }
}

/// Map a ureq result to `Ok(response)` for any 2xx, or a [`Verdict`]: a retryable
/// status or transport error is [`Verdict::Retry`]; any other status (4xx,
/// unexpected 3xx) is [`Verdict::Fatal`].
fn classify_status(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<ureq::http::Response<ureq::Body>, Verdict> {
    match result {
        Ok(resp) => {
            // http_status_as_error(false) means every status arrives here, so this
            // is the only place that maps a status to retry-or-fail.
            let code = resp.status().as_u16();
            if (200..300).contains(&code) {
                Ok(resp)
            } else if is_transient(code) {
                Err(Verdict::Retry(ClientError::Http(code)))
            } else {
                // redirects are disabled, so a 3xx here is unexpected and fatal.
                Err(Verdict::Fatal(ClientError::Http(code)))
            }
        }
        // Everything left is a transport-level failure: connect, TLS, timeout, IO.
        // All are worth retrying — a TLS failure against a host whose CA we pinned
        // is far more likely a not-yet-ready listener than a changed identity, and
        // the bearer token's short lifetime bounds how long we can keep trying.
        Err(e) => Err(Verdict::Retry(ClientError::Transport(transport_kind(&e)))),
    }
}

/// A short, stable, log-safe label for a transport error. Deliberately not the
/// full Display: these strings reach the controller in a /provision-failed
/// reason, and a URL or header could carry the bearer token (§9).
pub(crate) fn transport_kind(e: &ureq::Error) -> String {
    match e {
        ureq::Error::ConnectionFailed => "connection failed",
        ureq::Error::Timeout(_) => "timeout",
        ureq::Error::Tls(_) => "tls",
        ureq::Error::Io(_) => "io",
        ureq::Error::HostNotFound => "host not found",
        ureq::Error::TooManyRedirects => "too many redirects",
        _ => "transport",
    }
    .to_string()
}

/// Read a response body, failing if it would exceed `limit` bytes. Reads one byte
/// past the limit to distinguish "exactly at the limit" from "over".
fn read_capped(resp: ureq::http::Response<ureq::Body>, limit: u64) -> Result<Vec<u8>, ClientError> {
    let mut buf = Vec::new();
    resp.into_body()
        .into_reader()
        .take(limit + 1)
        .read_to_end(&mut buf)
        .map_err(|_| ClientError::Body)?;
    if buf.len() as u64 > limit {
        return Err(ClientError::BootstrapTooLarge);
    }
    Ok(buf)
}

/// Whether an HTTP status is a *transient* failure worth retrying. 408 (Request
/// Timeout) and 429 (Too Many Requests) plus all 5xx are transient; every other
/// 4xx (401/403/404/413/400) is terminal — retrying an auth or schema rejection
/// only wastes the token's short lifetime.
fn is_transient(status: u16) -> bool {
    matches!(status, 408 | 429) || (500..=599).contains(&status)
}

/// Backoff for retry `attempt` (0-based): [`BACKOFF_BASE`] doubled per attempt,
/// capped at [`BACKOFF_CAP`].
fn backoff(attempt: u32) -> Duration {
    let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
    BACKOFF_BASE
        .saturating_mul(factor.min(u32::MAX as u64) as u32)
        .min(BACKOFF_CAP)
}

/// The production sleeper used by [`run_with_retries`]; isolated so tests inject a
/// no-op and assert backoff scheduling without real waits.
fn sleep(d: Duration) {
    std::thread::sleep(d);
}

/// The outcome of one attempt inside [`run_with_retries`].
enum Attempt<T> {
    /// Success; return this value.
    Done(T),
    /// Transient failure; retry if the budget allows, else surface this error.
    Retry(ClientError),
    /// Terminal failure; stop immediately with this error.
    Fatal(ClientError),
}

/// Run `attempt` up to `max_attempts` times, sleeping [`backoff`] between retries
/// (via the injected `sleep`). Pure orchestration over the [`Attempt`] verdicts —
/// no network knowledge — so the retry logic is unit-tested with scripted
/// outcomes and a no-op sleeper.
fn run_with_retries<T>(
    max_attempts: u32,
    mut sleep: impl FnMut(Duration),
    mut attempt: impl FnMut(u32) -> Attempt<T>,
) -> Result<T, ClientError> {
    let mut last: Option<ClientError> = None;
    for n in 0..max_attempts {
        match attempt(n) {
            Attempt::Done(value) => return Ok(value),
            Attempt::Fatal(err) => return Err(err),
            Attempt::Retry(err) => {
                last = Some(err);
                if n + 1 < max_attempts {
                    sleep(backoff(n));
                }
            }
        }
    }
    Err(ClientError::RetriesExhausted(Box::new(
        last.unwrap_or(ClientError::Body),
    )))
}

/// Build a TLS config whose root store trusts *only* the CA in `ca_b64` (a
/// base64-encoded PEM bundle). No public roots, no platform trust store, no
/// insecure-skip path (§8).
///
/// ureq 3 builds the rustls ClientConfig itself from `RootCerts::Specific`, which
/// ends in the same `with_root_certificates(store)` call the hand-built config
/// used to make — the pinning property is unchanged.
///
/// One thing ureq does differently matters, and is why the parse below stays:
/// its `RootCerts::Specific` path uses `add_parsable_certificates`, which
/// *silently ignores* anything it cannot parse and only logs the count. Handing
/// it a half-valid bundle would leave a root store quietly missing certs — it
/// still fails closed at handshake time, but as an opaque TLS error rather than
/// a clear CaInvalid at startup. So we parse and validate every cert ourselves
/// first and keep the precise errors.
fn tls_config(ca_b64: &str) -> Result<ureq::tls::TlsConfig, ClientError> {
    use base64::Engine;
    use rustls::pki_types::{pem::PemObject, CertificateDer};

    let pem = base64::engine::general_purpose::STANDARD
        .decode(ca_b64.trim())
        .map_err(|_| ClientError::CaDecode)?;
    // PEM parsing lives in rustls-pki-types (re-exported by rustls); rustls-pemfile
    // is unmaintained (RUSTSEC-2025-0134) and is just a thin wrapper around this.
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ClientError::CaInvalid)?;
    if certs.is_empty() {
        return Err(ClientError::CaEmpty);
    }
    // Prove each cert is one rustls will actually accept as a root, so a bundle
    // ureq would silently drop fails here instead.
    let mut roots = RootCertStore::empty();
    for cert in &certs {
        roots
            .add(cert.clone())
            .map_err(|_| ClientError::CaInvalid)?;
    }

    let owned: Vec<ureq::tls::Certificate<'static>> = certs
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();

    Ok(ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::Specific(Arc::new(owned)))
        .build())
}

/// `{api}/api/v1/inspection/{ns}/{host}`, tolerating a trailing slash on `api`.
fn inspection_url(api: &str, namespace: &str, host: &str) -> String {
    format!(
        "{}/api/v1/inspection/{}/{}",
        api.trim_end_matches('/'),
        namespace,
        host
    )
}

/// `{api}/api/v1/bootstrap/{ns}/{host}`, tolerating a trailing slash on `api`.
fn bootstrap_url(api: &str, namespace: &str, host: &str) -> String {
    format!(
        "{}/api/v1/bootstrap/{}/{}",
        api.trim_end_matches('/'),
        namespace,
        host
    )
}

/// `{api}/api/v1/provisioned/{ns}/{host}`, tolerating a trailing slash on `api`.
fn provisioned_url(api: &str, namespace: &str, host: &str) -> String {
    format!(
        "{}/api/v1/provisioned/{}/{}",
        api.trim_end_matches('/'),
        namespace,
        host
    )
}

/// `{api}/api/v1/provision-failed/{ns}/{host}`, tolerating a trailing slash on `api`.
fn provision_failed_url(api: &str, namespace: &str, host: &str) -> String {
    format!(
        "{}/api/v1/provision-failed/{}/{}",
        api.trim_end_matches('/'),
        namespace,
        host
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // A throwaway self-signed CA certificate (ed25519, CA:TRUE), generated for
    // these tests only — no private key, no production trust value. It exists to
    // exercise the base64 -> PEM -> RootCertStore path in `tls_config`.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBSjCB/aADAgECAhRsJhyh9pg40zXiGsDkFsiW7SmcNzAFBgMrZXAwGjEYMBYG\n\
        A1UEAwwPYmVza2FyNy10ZXN0LWNhMCAXDTI2MDUzMTA2MTYxN1oYDzIxMjYwNTA3\n\
        MDYxNjE3WjAaMRgwFgYDVQQDDA9iZXNrYXI3LXRlc3QtY2EwKjAFBgMrZXADIQDl\n\
        axquhP/TUKRrDoFk08O+n0kA1tqD8nECivLB4nk/q6NTMFEwHQYDVR0OBBYEFHU/\n\
        NoBXWAUxxxuSmFeBgGUTH8qBMB8GA1UdIwQYMBaAFHU/NoBXWAUxxxuSmFeBgGUT\n\
        H8qBMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EADY4LA0q3gVXmd5w8RJci0nOh\n\
        utsoc3Hwix3MnSMV0389zry1JGD5pI8DvaI7Gu2HrfPr31Zgi5csUJdqauqjDg==\n\
        -----END CERTIFICATE-----\n";

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn urls_are_built_with_the_contract_paths() {
        assert_eq!(
            inspection_url("https://h:8082", "ns", "node-1"),
            "https://h:8082/api/v1/inspection/ns/node-1"
        );
        assert_eq!(
            bootstrap_url("https://h:8082", "ns", "node-1"),
            "https://h:8082/api/v1/bootstrap/ns/node-1"
        );
        assert_eq!(
            provisioned_url("https://h:8082", "ns", "node-1"),
            "https://h:8082/api/v1/provisioned/ns/node-1"
        );
        assert_eq!(
            provision_failed_url("https://h:8082", "ns", "node-1"),
            "https://h:8082/api/v1/provision-failed/ns/node-1"
        );
    }

    #[test]
    fn url_trailing_slash_on_api_is_tolerated() {
        assert_eq!(
            inspection_url("https://h:8082/", "ns", "h"),
            "https://h:8082/api/v1/inspection/ns/h"
        );
        assert_eq!(
            provisioned_url("https://h:8082/", "ns", "h"),
            "https://h:8082/api/v1/provisioned/ns/h"
        );
        assert_eq!(
            provision_failed_url("https://h:8082/", "ns", "h"),
            "https://h:8082/api/v1/provision-failed/ns/h"
        );
    }

    #[test]
    fn provisioned_body_is_the_fixed_advisory_json() {
        assert_eq!(PROVISIONED_BODY, br#"{"status":"provisioned"}"#);
    }

    #[test]
    fn provision_failed_body_is_the_reason_json() {
        assert_eq!(
            provision_failed_body("image digest mismatch").unwrap(),
            br#"{"reason":"image digest mismatch"}"#
        );
    }

    #[test]
    fn provision_failed_body_json_escapes_the_reason() {
        // A reason with a quote/backslash/control char must be JSON-escaped so it
        // cannot break out of the string or smuggle extra JSON fields.
        let body = provision_failed_body("bad \"quote\" and \\slash\nnewline").unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"reason":"bad \"quote\" and \\slash\nnewline"}"#
        );
        // The escaped body round-trips back to the exact reason.
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["reason"], "bad \"quote\" and \\slash\nnewline");
    }

    #[test]
    fn transient_statuses_retry_terminal_ones_do_not() {
        for s in [408, 429, 500, 502, 503, 504] {
            assert!(is_transient(s), "{s} should be transient");
        }
        for s in [400, 401, 403, 404, 413, 200, 202, 301] {
            assert!(!is_transient(s), "{s} should be terminal");
        }
    }

    #[test]
    fn backoff_is_monotonic_and_capped() {
        assert_eq!(backoff(0), BACKOFF_BASE);
        assert!(backoff(1) > backoff(0));
        assert!(backoff(2) > backoff(1));
        assert_eq!(backoff(3), Duration::from_secs(4));
        // Large attempts saturate at the cap rather than overflowing.
        assert_eq!(backoff(4), BACKOFF_CAP);
        assert_eq!(backoff(60), BACKOFF_CAP);
        assert_eq!(backoff(u32::MAX), BACKOFF_CAP);
    }

    #[test]
    fn retries_succeed_after_transient_failures() {
        let sleeps = Cell::new(0u32);
        let calls = Cell::new(0u32);
        let out = run_with_retries(
            5,
            |_| sleeps.set(sleeps.get() + 1),
            |_n| {
                let c = calls.get();
                calls.set(c + 1);
                if c < 2 {
                    Attempt::Retry(ClientError::Http(503))
                } else {
                    Attempt::Done(42u32)
                }
            },
        );
        assert_eq!(out.unwrap(), 42);
        assert_eq!(calls.get(), 3); // 2 retries + 1 success
        assert_eq!(sleeps.get(), 2); // one sleep before each retry
    }

    #[test]
    fn fatal_outcome_stops_immediately() {
        let calls = Cell::new(0u32);
        let sleeps = Cell::new(0u32);
        let out: Result<(), _> = run_with_retries(
            5,
            |_| sleeps.set(sleeps.get() + 1),
            |_n| {
                calls.set(calls.get() + 1);
                Attempt::Fatal(ClientError::Http(401))
            },
        );
        assert!(matches!(out, Err(ClientError::Http(401))));
        assert_eq!(calls.get(), 1); // no further attempts after a fatal
        assert_eq!(sleeps.get(), 0);
    }

    #[test]
    fn exhausting_retries_surfaces_the_last_error() {
        let calls = Cell::new(0u32);
        let sleeps = Cell::new(0u32);
        let out: Result<(), _> = run_with_retries(
            3,
            |_| sleeps.set(sleeps.get() + 1),
            |_n| {
                calls.set(calls.get() + 1);
                Attempt::Retry(ClientError::Http(503))
            },
        );
        match out {
            Err(ClientError::RetriesExhausted(inner)) => {
                assert!(matches!(*inner, ClientError::Http(503)));
            }
            other => panic!("expected RetriesExhausted, got {other:?}"),
        }
        assert_eq!(calls.get(), 3); // all attempts used
        assert_eq!(sleeps.get(), 2); // no sleep after the final attempt
    }

    /// Pins which fetch path may skip TLS verification. The controller callback
    /// may NOT — it trusts only the CA delivered on the cmdline (§8). The image
    /// fetch may, because the SHA-256 digest is the anchor there (§8.1). Both
    /// mistakes would be silent in normal operation, so assert the split rather
    /// than trusting the two call sites to stay correct.
    #[test]
    fn the_callback_verifies_and_only_the_image_fetch_does_not() {
        let callback = tls_config(&b64(TEST_CA_PEM.as_bytes())).expect("valid CA");
        assert!(
            !callback.disable_verification(),
            "the controller callback must verify"
        );
        assert!(
            matches!(callback.root_certs(), ureq::tls::RootCerts::Specific(_)),
            "the callback must trust only the delivered CA, not platform or webpki roots"
        );

        assert!(
            crate::image::no_verify_tls_config().disable_verification(),
            "the image fetch is the one path that skips verification"
        );
    }

    #[test]
    fn tls_config_accepts_a_valid_ca() {
        let cfg = tls_config(&b64(TEST_CA_PEM.as_bytes()));
        assert!(cfg.is_ok(), "valid CA should build a config: {cfg:?}");
    }

    #[test]
    fn tls_config_rejects_non_base64() {
        // '!' is outside the base64 alphabet.
        assert!(matches!(
            tls_config("not base64!!!"),
            Err(ClientError::CaDecode)
        ));
    }

    #[test]
    fn tls_config_rejects_base64_that_is_not_a_certificate() {
        // Valid base64, but the bytes are not a PEM certificate -> no certs found.
        let not_a_cert = b64(b"hello, this is plainly not a PEM certificate");
        assert!(matches!(tls_config(&not_a_cert), Err(ClientError::CaEmpty)));
    }
}
