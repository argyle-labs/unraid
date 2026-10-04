//! Masking of secret-looking env values in everything these verbs return.
//!
//! The declared `role = "admin"` is not yet enforced for plugin tools
//! (argyle-labs/orca#763), so dry-run output may reach non-admins.

use plugin_toolkit::prelude::sha256_hex;

use super::template::xml_escape;

/// Env names whose values are masked: (?i)(pass|token|secret|key|auth|cred|cookie|session|private).
pub fn is_secret_key(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "pass", "token", "secret", "key", "auth", "cred", "cookie", "session", "private",
    ]
    .iter()
    .any(|p| n.contains(p))
}

/// `<redacted:xxxxxxxx>` — the first 8 hex of the value's sha256, so two
/// outputs can be compared without revealing the value.
pub fn token(value: &str) -> String {
    format!("<redacted:{}>", &sha256_hex(value.as_bytes())[..8])
}

pub fn mask(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        token(value)
    } else {
        value.to_string()
    }
}

/// Textual masking of known secret values in free-form text (errors, notes).
/// Values shorter than 4 characters are only masked structurally, where the
/// key is known; replacing them as substrings would mangle unrelated text.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    values: Vec<String>,
}

impl Redactor {
    pub fn from_env<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut r = Redactor::default();
        for (k, v) in pairs {
            r.add(k, v);
        }
        r
    }

    pub fn add(&mut self, key: &str, value: &str) {
        if is_secret_key(key) && !value.is_empty() && !self.values.iter().any(|v| v == value) {
            self.values.push(value.to_string());
            self.values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        }
    }

    pub fn text(&self, s: &str) -> String {
        let mut out = s.to_string();
        for v in self.values.iter().filter(|v| v.len() >= 4) {
            let t = token(v);
            for form in [
                v.clone(),
                xml_escape(v),
                v.replace('\'', r"'\''"),
                format!("{v:?}").trim_matches('"').to_string(),
            ] {
                if !form.is_empty() {
                    out = out.replace(&form, &t);
                }
            }
        }
        out
    }
}

/// Mask secret Variable values (element text and `Default`) in template XML,
/// whoever wrote it.
pub fn mask_template_xml(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<Config ") {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let Some(open_end) = tail.find('>') else {
            out.push_str(tail);
            return out;
        };
        let open = &tail[..open_end];
        let self_closing = open.ends_with('/');
        let target = attr(open, "Target").or_else(|| attr(open, "Name"));
        let secret = attr(open, "Type").as_deref() == Some("Variable")
            && target.as_deref().is_some_and(is_secret_key);
        if !secret || self_closing {
            out.push_str(&tail[..=open_end]);
            rest = &tail[open_end + 1..];
            continue;
        }
        let Some(close) = tail.find("</Config>") else {
            out.push_str(tail);
            return out;
        };
        let inner = &tail[open_end + 1..close];
        let masked_open = match attr(open, "Default") {
            Some(d) if !d.is_empty() => open.replacen(
                &format!("Default=\"{}\"", xml_escape(&d)),
                &format!("Default=\"{}\"", xml_escape(&token(&d))),
                1,
            ),
            _ => open.to_string(),
        };
        out.push_str(&masked_open);
        out.push('>');
        if !inner.is_empty() {
            let value = super::template::xml_unescape(inner);
            out.push_str(&xml_escape(&token(&value)));
        }
        out.push_str("</Config>");
        rest = &tail[close + "</Config>".len()..];
    }
    out.push_str(rest);
    out
}

/// Unescaped value of attribute `name` in an opening tag.
fn attr(open: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let s = open.find(&needle)? + needle.len();
    let e = open[s..].find('"')? + s;
    Some(super::template::xml_unescape(&open[s..e]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_keys_match_case_insensitively() {
        for k in [
            "DB_PASSWORD",
            "api_key",
            "AuthToken",
            "SESSION_SECRET",
            "Private_X",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in ["PUID", "TZ", "ASR_MODEL"] {
            assert!(!is_secret_key(k), "{k}");
        }
    }

    #[test]
    fn template_xml_masking_hides_value_and_default() {
        let xml = r#"<Config Name="DB_PASSWORD" Target="DB_PASSWORD" Default="s3cr&amp;t" Mode="" Type="Variable" Mask="true">s3cr&amp;t</Config>
<Config Name="PUID" Target="PUID" Default="99" Mode="" Type="Variable">99</Config>"#;
        let out = mask_template_xml(xml);
        assert!(!out.contains("s3cr"), "{out}");
        assert!(out.contains(&xml_escape(&token("s3cr&t"))));
        assert!(out.contains(">99</Config>"));
    }

    #[test]
    fn redactor_masks_raw_xml_and_shell_forms() {
        let r = Redactor::from_env([("API_KEY", "it's&secret"), ("PUID", "99")]);
        let t = token("it's&secret");
        assert_eq!(r.text("x it's&secret y"), format!("x {t} y"));
        assert_eq!(r.text("it&apos;s&amp;secret"), t);
        assert_eq!(r.text(r"'it'\''s&secret'"), format!("'{t}'"));
        assert_eq!(r.text("99"), "99");
    }
}
