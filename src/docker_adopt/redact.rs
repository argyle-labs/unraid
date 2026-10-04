//! Masking of secret-looking values (env, labels, command flags, URL
//! passwords) in everything these verbs return.
//!
//! The declared `role = "admin"` is not yet enforced for plugin tools
//! (argyle-labs/orca#763), so dry-run output may reach non-admins.

use std::sync::OnceLock;

use plugin_toolkit::hash::{hex_encode, sha256};

use super::template::xml_escape;

/// Env names (and `--flag` names) whose values are masked:
/// (?i)(pass|token|secret|key|auth|cred|cookie|session|private).
pub fn is_secret_key(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "pass", "token", "secret", "key", "auth", "cred", "cookie", "session", "private",
    ]
    .iter()
    .any(|p| n.contains(p))
}

/// Label keys whose values are masked: (?i)(auth|pass|token|secret|key|users),
/// `users` covering basic-auth user lists.
pub fn is_secret_label_key(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["auth", "pass", "token", "secret", "key", "users"]
        .iter()
        .any(|p| n.contains(p))
}

/// Per-process random key, so a token cannot be checked against guesses.
fn hmac_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut k))
            .is_err()
        {
            k = sha256(super::host::random_suffix().as_bytes());
        }
        k
    })
}

fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let inner = sha256(&[&ipad[..], msg].concat());
    sha256(&[&opad[..], &inner[..]].concat())
}

/// `<redacted:xxxxxxxx>` — a keyed (per-process) digest prefix: equal values
/// in one output get equal tokens, but a token reveals nothing offline.
pub fn token(value: &str) -> String {
    format!(
        "<redacted:{}>",
        &hex_encode(&hmac_sha256(hmac_key(), value.as_bytes()))[..8]
    )
}

/// The password in a `scheme://user:password@host` value.
pub fn url_password(v: &str) -> Option<&str> {
    let after = v.find("://")? + 3;
    let rest = &v[after..];
    let auth_end = rest.find('@')?;
    if rest[..auth_end].contains('/') {
        return None;
    }
    let colon = rest[..auth_end].find(':')?;
    let pw = &rest[colon + 1..auth_end];
    (!pw.is_empty()).then_some(pw)
}

fn mask_url(v: &str) -> String {
    match url_password(v) {
        Some(pw) => v.replacen(&format!(":{pw}@"), &format!(":{}@", token(pw)), 1),
        None => v.to_string(),
    }
}

/// An env value as shown: whole value masked for a secret name, otherwise
/// any URL password inside it.
pub fn mask(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        token(value)
    } else {
        mask_url(value)
    }
}

pub fn mask_label(key: &str, value: &str) -> String {
    if is_secret_label_key(key) {
        token(value)
    } else {
        mask_url(value)
    }
}

/// Values of secret-looking `--flag value` / `--flag=value` args.
pub fn secret_cmd_values(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        let Some(flag) = a.strip_prefix('-') else {
            continue;
        };
        let flag = flag.trim_start_matches('-');
        match flag.split_once('=') {
            Some((f, v)) if is_secret_key(f) && !v.is_empty() => out.push(v.to_string()),
            None if is_secret_key(flag) => {
                if let Some(v) = it.next_if(|n| !n.starts_with('-')) {
                    out.push(v.clone());
                }
            }
            _ => {}
        }
    }
    out
}

pub fn mask_cmd(args: &[String]) -> Vec<String> {
    let secrets = secret_cmd_values(args);
    args.iter()
        .map(|a| {
            let mut a = a.clone();
            for s in &secrets {
                a = a.replace(s.as_str(), &token(s));
            }
            mask_url(&a)
        })
        .collect()
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

    fn push(&mut self, value: &str) {
        if !value.is_empty() && !self.values.iter().any(|v| v == value) {
            self.values.push(value.to_string());
            self.values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        }
    }

    /// Register an env pair: the value if the name is secret, else any URL
    /// password in it.
    pub fn add(&mut self, key: &str, value: &str) {
        if is_secret_key(key) {
            self.push(value);
        } else if let Some(pw) = url_password(value) {
            self.push(pw);
        }
    }

    pub fn add_label(&mut self, key: &str, value: &str) {
        if is_secret_label_key(key) {
            self.push(value);
        } else if let Some(pw) = url_password(value) {
            self.push(pw);
        }
    }

    pub fn add_cmd(&mut self, args: &[String]) {
        for v in secret_cmd_values(args) {
            self.push(&v);
        }
        for a in args {
            if let Some(pw) = url_password(a) {
                self.push(pw);
            }
        }
    }

    /// Register everything secret in a spec: env, labels and command args.
    pub fn add_spec(&mut self, spec: &super::spec::RunSpec) {
        for (k, v) in &spec.env {
            self.add(k, v);
        }
        for (k, v) in &spec.labels {
            self.add_label(k, v);
        }
        self.add_cmd(&spec.cmd);
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
        let is_var = attr(open, "Type").as_deref() == Some("Variable");
        let secret = is_var && target.as_deref().is_some_and(is_secret_key);
        if is_var && !secret && !self_closing {
            // Not a secret name, but a URL password inside the value is.
            let Some(close) = tail.find("</Config>") else {
                out.push_str(tail);
                return out;
            };
            let inner = super::template::xml_unescape(&tail[open_end + 1..close]);
            let open_masked = match attr(open, "Default") {
                Some(d) if url_password(&d).is_some() => open.replacen(
                    &format!("Default=\"{}\"", xml_escape(&d)),
                    &format!("Default=\"{}\"", xml_escape(&mask_url(&d))),
                    1,
                ),
                _ => open.to_string(),
            };
            out.push_str(&open_masked);
            out.push('>');
            out.push_str(&xml_escape(&mask_url(&inner)));
            out.push_str("</Config>");
            rest = &tail[close + "</Config>".len()..];
            continue;
        }
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

    #[test]
    fn token_is_keyed_not_a_plain_hash_prefix() {
        let plain = &plugin_toolkit::prelude::sha256_hex(b"hunter2")[..8];
        assert_ne!(token("hunter2"), format!("<redacted:{plain}>"));
        assert_eq!(token("hunter2"), token("hunter2"));
        assert_ne!(token("hunter2"), token("hunter3"));
    }

    #[test]
    fn url_passwords_labels_and_cmd_flags_are_masked() {
        assert_eq!(url_password("postgres://u:pw1@db:5432/x"), Some("pw1"));
        assert_eq!(url_password("https://host/a:b@c"), None);
        assert_eq!(url_password("http://user@host"), None);
        let m = mask("DATABASE_URL", "postgres://u:pw1@db/x");
        assert!(
            !m.contains("pw1") && m.starts_with("postgres://u:<redacted:"),
            "{m}"
        );
        assert!(
            mask_label("traefik.http.middlewares.a.basicauth.users", "u:$apr1$x")
                .starts_with("<redacted:")
        );
        assert_eq!(mask_label("traefik.enable", "true"), "true");
        let args: Vec<String> = [
            "--model",
            "tiny",
            "--password",
            "pw-a",
            "--api-token=tok-b",
            "--x",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(secret_cmd_values(&args), vec!["pw-a", "tok-b"]);
        let masked = mask_cmd(&args).join(" ");
        assert!(
            !masked.contains("pw-a") && !masked.contains("tok-b"),
            "{masked}"
        );
        assert!(masked.contains("--model tiny"));
    }

    #[test]
    fn template_xml_masks_url_passwords_in_plain_variables() {
        let xml = r#"<Config Name="DB_URL" Target="DB_URL" Default="mysql://a:p4ss@h/d" Mode="" Type="Variable">mysql://a:p4ss@h/d</Config>"#;
        let out = mask_template_xml(xml);
        assert!(!out.contains("p4ss"), "{out}");
        assert!(out.contains("mysql://a:"), "{out}");
    }
}
