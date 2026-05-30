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
    /// `beskar7.target` — OS image URL to kexec into. Non-secret.
    pub target: String,
    /// `beskar7.ca` — base64-encoded PEM of the CA used to verify the callback's
    /// TLS certificate. Kept as the raw base64 string; decoding and validation
    /// are the TLS client's responsibility (§8). Non-secret (a public CA cert).
    pub ca: String,
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
        let mut ca = None;
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
                "beskar7.ca" => ca = non_empty(value),
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
            ca: ca.expect("ca present"),
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

    // A realistic cmdline: the beskar7.* params interleaved with ordinary kernel
    // arguments the parser must ignore.
    const FULL: &str = "BOOT_IMAGE=/vmlinuz \
        beskar7.api=https://beskar7.example.com:8082 \
        beskar7.namespace=tenant-a \
        beskar7.host=node-01 \
        beskar7.token=Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWprbA \
        beskar7.target=https://images.example.com/talos-1.7-amd64.raw.xz \
        beskar7.ca=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg== \
        beskar7.timeout=600 beskar7.debug=true console=ttyS0,115200n8 quiet";

    fn minimal() -> String {
        "beskar7.api=https://h:8082 beskar7.namespace=ns beskar7.host=h \
         beskar7.token=tok beskar7.target=https://t beskar7.ca=Zm9v"
            .to_string()
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
        assert_eq!(
            p.target,
            "https://images.example.com/talos-1.7-amd64.raw.xz"
        );
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
    fn base64_ca_padding_is_preserved() {
        // Padding '=' must survive split_once on the first '='.
        let line = "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token=t beskar7.target=https://t beskar7.ca=YWJjZGVmZ2hpamts==";
        let p = BootParams::parse(line).expect("valid");
        assert_eq!(p.ca, "YWJjZGVmZ2hpamts==");
    }

    #[test]
    fn missing_one_required_is_named() {
        let line = "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.target=https://t beskar7.ca=Zm9v"; // no token
        match BootParams::parse(line).unwrap_err() {
            CmdlineError::MissingRequired(names) => {
                assert!(names.contains("beskar7.token"), "names: {names}");
                assert!(!names.contains("beskar7.api"));
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
            "beskar7.ca",
        ] {
            assert!(msg.contains(key), "{key} not reported in {msg:?}");
        }
    }

    #[test]
    fn empty_required_value_is_treated_as_missing() {
        let line = "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token= beskar7.target=https://t beskar7.ca=Zm9v"; // empty token
        let err = BootParams::parse(line).unwrap_err();
        assert!(matches!(
            err,
            CmdlineError::MissingRequired(ref s) if s.contains("beskar7.token")
        ));
    }

    #[test]
    fn invalid_timeout_is_rejected() {
        let line = "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token=t beskar7.target=https://t beskar7.ca=Zm9v beskar7.timeout=soon";
        assert!(matches!(
            BootParams::parse(line),
            Err(CmdlineError::InvalidTimeout)
        ));
    }

    #[test]
    fn duplicate_key_last_wins() {
        let line = "beskar7.api=https://first beskar7.api=https://second \
            beskar7.namespace=n beskar7.host=h beskar7.token=t \
            beskar7.target=https://t beskar7.ca=Zm9v";
        let p = BootParams::parse(line).expect("valid");
        assert_eq!(p.api, "https://second");
    }

    #[test]
    fn non_beskar7_params_are_ignored() {
        let line = "root=/dev/sda1 ro beskar7.api=https://h beskar7.namespace=n \
            beskar7.host=h beskar7.token=t beskar7.target=https://t beskar7.ca=Zm9v \
            quiet splash";
        assert!(BootParams::parse(line).is_ok());
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
        let line = "beskar7.api=https://h beskar7.namespace=n beskar7.host=h \
            beskar7.token=t beskar7.target=https://t beskar7.ca=Zm9v beskar7.debug=yes";
        let p = BootParams::parse(line).expect("valid");
        assert!(!p.debug);
    }
}
