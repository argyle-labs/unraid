//! Unraid version identity + dispatch helper.
//!
//! The set of supported versions is whatever
//! [`crate::generated::SUPPORTED_VERSIONS`] reports — that table is
//! generated at build time from the files in
//! `projects/plugins/unraid/schemas/`. Adding a new schema is purely
//! additive: drop the JSON in, rebuild, and the new version is picked
//! up here without code edits.

use crate::generated::SUPPORTED_VERSIONS;

/// A probed Unraid version paired with the codegen module that backs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnraidVersion {
    /// Raw version string as reported by `vars.version` ("7.3.1",
    /// "7.3.1-rc1", …).
    pub raw: String,
    /// Codegen module name (`"v7_3_1"`) when we have a matching schema
    /// committed, else `None` — caller should fall back to the newest
    /// supported version and warn.
    pub module: Option<&'static str>,
}

impl UnraidVersion {
    /// Match a probed string against the committed schemas. Pre-release
    /// suffixes (`"-rc1"`, `"+build42"`) are stripped before lookup so
    /// `7.3.1-rc1` lines up with the `7.3.1` schema.
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw
            .split(|c: char| !c.is_ascii_digit() && c != '.')
            .next()
            .unwrap_or(raw);
        let module = SUPPORTED_VERSIONS
            .iter()
            .find(|(v, _)| *v == trimmed)
            .map(|(_, m)| *m);
        Self {
            raw: raw.to_string(),
            module,
        }
    }

    /// All versions we have generated typed clients for, sorted.
    pub fn supported() -> &'static [(&'static str, &'static str)] {
        SUPPORTED_VERSIONS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_committed_schema() {
        // Whatever is committed at the time of this test must include 7.3.1.
        let v = UnraidVersion::parse("7.3.1");
        assert_eq!(v.module, Some("v7_3_1"));
    }

    #[test]
    fn strips_prerelease_and_build_suffix() {
        assert_eq!(UnraidVersion::parse("7.3.1-rc1").module, Some("v7_3_1"));
        assert_eq!(UnraidVersion::parse("7.3.1+ci").module, Some("v7_3_1"));
    }

    #[test]
    fn unknown_returns_none_module_but_preserves_raw() {
        let v = UnraidVersion::parse("99.0.0");
        assert!(v.module.is_none());
        assert_eq!(v.raw, "99.0.0");
    }

    #[test]
    fn supported_list_is_non_empty() {
        assert!(!UnraidVersion::supported().is_empty());
    }
}
