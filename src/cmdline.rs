//! Parse the `beskar7.*` kernel cmdline parameters that the controller's `/boot`
//! endpoint renders for the inspector (contract §5). The inspector reads these
//! from `/proc/cmdline`.
//!
//! Security (contract §5/§9): the cmdline carries the bearer token
//! (`beskar7.token`). It is wrapped in [`Secret`] here so downstream code cannot
//! accidentally log it, and parse errors name only parameter *keys*, never their
//! values.

use std::time::Duration;

use crate::secret::Secret;

/// The boot parameters the controller renders onto the kernel cmdline (§5).
///
/// `Debug` is derived: every field except [`token`](Self::token) is non-secret,
/// and the token field redacts itself, so debug-formatting `BootParams` cannot
/// leak the bearer token. (It is still not the full `/proc/cmdline`, which §9
/// forbids logging.)
#[derive(Debug, Clone)]
pub struct BootParams {
    /// `beskar7.api` — externally-reachable HTTPS base URL of the callback
    /// server. Scheme/`.svc` validation is the TLS client's job (§8), not the
    /// parser's.
    pub api: String,
    /// `beskar7.namespace` — PhysicalHost namespace (endpoint path segment).
    pub namespace: String,
    /// `beskar7.host` — PhysicalHost name (endpoint path segment).
    pub host: String,
    /// `beskar7.token` — per-host bearer token. Secret.
    pub token: Secret,
    /// `beskar7.target` — URL of the whole-disk OS image (a Kairos raw image)
    /// the inspector streams onto the target disk. Fetched over plain HTTP; its
    /// integrity is anchored by [`target_digest`](Self::target_digest), not TLS
    /// (contract §8.1). Non-secret.
    pub target: String,
    /// `beskar7.target-digest` — expected SHA-256 of the bytes at
    /// [`target`](Self::target), as the raw `sha256:<64-lowercase-hex>` string
    /// the controller rendered. This is the integrity/authenticity anchor for
    /// the target image (contract §8.1): the inspector refuses to mount, inject
    /// user-data, or reboot unless the written image hashes to this value. Kept
    /// as the raw string here; format parsing and the constant-length compare are
    /// the image fetcher's responsibility (§8.1), mirroring how
    /// [`ca`](Self::ca) defers decoding to the TLS client. Non-secret.
    pub target_digest: String,
    /// `beskar7.ca` — base64-encoded PEM of the CA used to verify the callback's
    /// TLS certificate. Kept as the raw base64 string; decoding and validation
    /// are the TLS client's responsibility (§8). Non-secret (a public CA cert).
    pub ca: String,
    /// `beskar7.disk` — optional operator override pinning the deployment target
    /// disk (a `/dev/...` path, a `by-id`/`by-path` symlink, or a bare kernel
    /// name). When `None`, [`crate::target_disk::select`] auto-selects the
    /// smallest eligible whole disk; when `Some`, that exact device is used (and
    /// the deploy aborts rather than falling back if it is ineligible). Resolution
    /// and eligibility are `target_disk`'s responsibility (contract §5 / §9.1
    /// step 2). Non-secret.
    pub disk: Option<String>,
    /// `beskar7.timeout` — optional inspector-side overall timeout.
    pub timeout: Option<Duration>,
    /// `beskar7.debug` — verbose logging / debug shell on failure.
    pub debug: bool,
}

/// Errors from parsing the kernel cmdline. Messages never include parameter
/// *values* (one of which is the bearer token).
#[derive(Debug, thiserror::Error)]
pub enum CmdlineError {
    /// One or more required `beskar7.*` parameters were absent or empty. Only the
    /// parameter *names* are reported.
    #[error("missing or empty required kernel cmdline parameter(s): {0}")]
    MissingRequired(String),
    /// `beskar7.timeout` was present but not a non-negative integer of seconds.
    #[error("beskar7.timeout is not a valid non-negative integer number of seconds")]
    InvalidTimeout,
    /// `/proc/cmdline` could not be read.
    #[error("reading /proc/cmdline")]
    Io(#[from] std::io::Error),
}

impl BootParams {
    /// Read and parse `/proc/cmdline`.
    pub fn from_proc_cmdline() -> Result<Self, CmdlineError> {
        let raw = std::fs::read_to_string("/proc/cmdline")?;
        Self::parse(&raw)
    }

    /// Parse boot parameters from a raw kernel cmdline string.
    ///
    /// Non-`beskar7.*` parameters are ignored. On a duplicate `beskar7.*` key the
    /// last occurrence wins, matching kernel cmdline convention.
    pub fn parse(cmdline: &str) -> Result<Self, CmdlineError> {
        let mut api = None;
        let mut namespace = None;
        let mut host = None;
        let mut token = None;
        let mut target = None;
        let mut target_digest = None;
        let mut ca = None;
        let mut disk = None;
        let mut timeout = None;
        let mut debug = false;

        for param in cmdline.split_ascii_whitespace() {
            // Split on the FIRST '=' so that base64 '=' padding in beskar7.ca is
            // preserved in the value.
            let Some((key, value)) = param.split_once('=') else {
                continue;
            };
            match key {
                "beskar7.api" => api = non_empty(value),
                "beskar7.namespace" => namespace = non_empty(value),
                "beskar7.host" => host = non_empty(value),
                "beskar7.token" => token = non_empty(value),
                "beskar7.target" => target = non_empty(value),
                "beskar7.target-digest" => target_digest = non_empty(value),
                "beskar7.ca" => ca = non_empty(value),
                "beskar7.disk" => disk = non_empty(value),
                "beskar7.timeout" => {
                    if !value.is_empty() {
                        let secs: u64 = value.parse().map_err(|_| CmdlineError::InvalidTimeout)?;
                        timeout = Some(Duration::from_secs(secs));
                    }
                }
                "beskar7.debug" => debug = value.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }

        let mut missing = Vec::new();
        for (name, present) in [
            ("beskar7.api", api.is_some()),
            ("beskar7.namespace", namespace.is_some()),
            ("beskar7.host", host.is_some()),
            ("beskar7.token", token.is_some()),
            ("beskar7.target", target.is_some()),
            ("beskar7.target-digest", target_digest.is_some()),
            ("beskar7.ca", ca.is_some()),
        ] {
            if !present {
                missing.push(name);
            }
        }
        if !missing.is_empty() {
            return Err(CmdlineError::MissingRequired(missing.join(", ")));
        }

        Ok(BootParams {
            // Each `expect` is guarded by the missing-required check above.
            api: api.expect("api present"),
            namespace: namespace.expect("namespace present"),
            host: host.expect("host present"),
            token: Secret::new(token.expect("token present")),
            target: target.expect("target present"),
            target_digest: target_digest.expect("target_digest present"),
            ca: ca.expect("ca present"),
            disk,
            timeout,
            debug,
        })
    }
}

/// `Some(value)` if non-empty, else `None`, so an empty required parameter is
/// treated as missing.
fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid digest literal (the SHA-256 of the empty input) reused across the
    // success-path fixtures; the parser stores it verbatim, so any well-formed
    // value works here.
    const DIGEST: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // A realistic cmdline: the beskar7.* params interleaved with ordinary kernel
    // arguments the parser must ignore.
    const FULL: &str = "BOOT_IMAGE=/vmlinuz \
        beskar7.api=https://beskar7.example.com:8082 \
        beskar7.namespace=tenant-a \
        beskar7.host=node-01 \
        beskar7.token=Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWprbA \
        beskar7.target=https://images.example.com/kairos-v3-amd64.raw \
        beskar7.target-digest=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
        beskar7.ca=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg== \
        beskar7.timeout=600 beskar7.debug=true console=ttyS0,115200n8 quiet";

    fn minimal() -> String {
        format!(
            "beskar7.api=https://h:8082 beskar7.namespace=ns beskar7.host=h \
             beskar7.token=tok beskar7.target=https://t beskar7.target-digest={DIGEST} \
             beskar7.ca=Zm9v"
        )
    }

    #[test]
    fn parses_full_cmdline() {
        let p = BootParams::parse(FULL).expect("valid cmdline");
        assert_eq!(p.api, "https://beskar7.example.com:8082");
        assert_eq!(p.namespace, "tenant-a");
        assert_eq!(p.host, "node-01");
        assert_eq!(
            p.token.expose(),
            "Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWprbA"
        );
        assert_eq!(p.target, "https://images.example.com/kairos-v3-amd64.raw");
        assert_eq!(p.target_digest, DIGEST);
        assert_eq!(p.ca, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==");
        assert_eq!(p.timeout, Some(Duration::from_secs(600)));
        assert!(p.debug);
    }

    #[test]
    fn minimal_required_only_has_no_timeout_and_no_debug() {
        let p = BootParams::parse(&minimal()).expect("valid");
        assert_eq!(p.timeout, None);
        assert!(!p.debug);
    }

    #[test]
    fn optional_disk_is_none_when_absent_and_some_when_set() {
        // Absent in the minimal cmdline.
        let p = BootParams::parse(&minimal()).expect("valid");
        assert_eq!(p.disk, None);

        // Present (a by-id path) is captured verbatim; resolution is target_disk's job.
        let pinned = format!("{} beskar7.disk=/dev/disk/by-id/nvme-FOO", minimal());
        let p = BootParams::parse(&pinned).expect("valid");
        assert_eq!(p.disk.as_deref(), Some("/dev/disk/by-id/nvme-FOO"));
    }

    #[test]
    fn empty_disk_value_is_treated_as_absent() {
        let line = format!("{} beskar7.disk=", minimal());
        let p = BootParams::parse(&line).expect("valid");
        assert_eq!(p.disk, None);
    }

    #[test]
    fn base64_ca_padding_is_preserved() {
        // Padding '=' must survive split_once on the first '='.
        let line = format!(
            "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token=t beskar7.target=https://t beskar7.target-digest={DIGEST} \
            beskar7.ca=YWJjZGVmZ2hpamts=="
        );
        let p = BootParams::parse(&line).expect("valid");
        assert_eq!(p.ca, "YWJjZGVmZ2hpamts==");
    }

    #[test]
    fn missing_one_required_is_named() {
        // Everything present except the token.
        let line = format!(
            "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.target=https://t beskar7.target-digest={DIGEST} beskar7.ca=Zm9v"
        );
        match BootParams::parse(&line).unwrap_err() {
            CmdlineError::MissingRequired(names) => {
                assert!(names.contains("beskar7.token"), "names: {names}");
                assert!(!names.contains("beskar7.api"));
                assert!(!names.contains("beskar7.target-digest"), "names: {names}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn missing_target_digest_is_named() {
        // The v2 param: present-but-required check fires when it is absent.
        let line = "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token=t beskar7.target=https://t beskar7.ca=Zm9v"; // no target-digest
        match BootParams::parse(line).unwrap_err() {
            CmdlineError::MissingRequired(names) => {
                assert!(names.contains("beskar7.target-digest"), "names: {names}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn missing_several_required_are_all_named() {
        let err = BootParams::parse("beskar7.debug=true").unwrap_err();
        let msg = err.to_string();
        for key in [
            "beskar7.api",
            "beskar7.namespace",
            "beskar7.host",
            "beskar7.token",
            "beskar7.target",
            "beskar7.target-digest",
            "beskar7.ca",
        ] {
            assert!(msg.contains(key), "{key} not reported in {msg:?}");
        }
    }

    #[test]
    fn empty_required_value_is_treated_as_missing() {
        let line = format!(
            "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token= beskar7.target=https://t beskar7.target-digest={DIGEST} \
            beskar7.ca=Zm9v"
        ); // empty token
        let err = BootParams::parse(&line).unwrap_err();
        assert!(matches!(
            err,
            CmdlineError::MissingRequired(ref s) if s.contains("beskar7.token")
        ));
    }

    #[test]
    fn invalid_timeout_is_rejected() {
        let line = format!(
            "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token=t beskar7.target=https://t beskar7.target-digest={DIGEST} \
            beskar7.ca=Zm9v beskar7.timeout=soon"
        );
        assert!(matches!(
            BootParams::parse(&line),
            Err(CmdlineError::InvalidTimeout)
        ));
    }

    #[test]
    fn duplicate_key_last_wins() {
        let line = format!(
            "beskar7.api=https://first beskar7.api=https://second \
            beskar7.namespace=n beskar7.host=h beskar7.token=t \
            beskar7.target=https://t beskar7.target-digest={DIGEST} beskar7.ca=Zm9v"
        );
        let p = BootParams::parse(&line).expect("valid");
        assert_eq!(p.api, "https://second");
    }

    #[test]
    fn non_beskar7_params_are_ignored() {
        let line = format!(
            "root=/dev/sda1 ro beskar7.api=https://h beskar7.namespace=n \
            beskar7.host=h beskar7.token=t beskar7.target=https://t \
            beskar7.target-digest={DIGEST} beskar7.ca=Zm9v quiet splash"
        );
        assert!(BootParams::parse(&line).is_ok());
    }

    #[test]
    fn debug_output_redacts_the_token() {
        let p = BootParams::parse(FULL).expect("valid");
        let rendered = format!("{p:?}");
        assert!(
            !rendered.contains("Zm9vYmFyYmF6"),
            "token leaked: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn debug_flag_is_false_unless_exactly_true() {
        let line = format!(
            "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token=t beskar7.target=https://t beskar7.target-digest={DIGEST} \
            beskar7.ca=Zm9v beskar7.debug=yes"
        );
        let p = BootParams::parse(&line).expect("valid");
        assert!(!p.debug);
    }
}
