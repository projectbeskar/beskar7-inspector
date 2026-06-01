//! A minimal redacting wrapper for secret strings.
//!
//! The only secret the inspector handles is the per-host bearer token
//! (`beskar7.token`), delivered on the kernel cmdline. Wrapping it in [`Secret`]
//! keeps it out of `Debug` output and accidental logs: the value is reachable
//! only through [`Secret::expose`], so every read is deliberate and greppable.
//! See the contract §5/§9 — the token MUST NOT be logged or persisted.

use std::fmt;

use zeroize::Zeroize;

/// A secret string that never reveals its contents via `Debug`. It deliberately
/// implements neither `Display` nor `PartialEq`, to prevent accidental logging
/// and non-constant-time comparison. Read the value only via [`Secret::expose`].
///
/// The inner value is zeroed on drop (contract §9: the bearer token must not
/// linger in freed memory), via [`Zeroize`].
#[derive(Clone)]
pub struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying secret. Call this only at the point of use (e.g.
    /// building the `Authorization: Bearer` header) — never to log or format it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("super-secret-token-value");
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret([redacted])");
        assert!(!rendered.contains("super-secret-token-value"));
    }

    #[test]
    fn expose_returns_the_value() {
        let s = Secret::new("abc123");
        assert_eq!(s.expose(), "abc123");
    }
}
