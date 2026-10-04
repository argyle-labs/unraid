//! Masking of secret-looking values (env, labels, command flags, URL
//! passwords) in everything these verbs return.
//!
//! The declared `role = "admin"` is not yet enforced for plugin tools
//! (argyle-labs/orca#763), so dry-run output may reach non-admins.

use std::sync::OnceLock;

use plugin_toolkit::hash::{hex_encode, sha256};

use super::template::xml_escape;

/// Substrings that mark a name as secret, case-insensitively.
const SECRET_PARTS: &[&str] = &[
    "pass", "pwd", "token", "secret", "key", "auth", "cred", "cookie", "session", "private", "jwt",
    "salt", "dsn", "webhook", "signing", "encrypt",
];

/// `pw` only as a whole word (`DB_PW`, `pw`), not inside `pwm` or `upward`.
fn has_pw_word(n: &str) -> bool {
    n.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| w == "pw")
}

/// Env, flag and log-opt names whose values are masked.
pub fn is_secret_key(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SECRET_PARTS.iter().any(|p| n.contains(p)) || has_pw_word(&n)
}

/// Label keys whose values are masked: the env set plus `users`, which
/// covers basic-auth user lists.
pub fn is_secret_label_key(name: &str) -> bool {
    is_secret_key(name) || name.to_ascii_lowercase().contains("users")
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

/// Byte range of the password in a `scheme://user:password@host` value. The
/// authority ends at the first `/`, `?` or `#`; userinfo ends at its last `@`
/// (a raw `@` inside a password is common).
fn url_password_range(v: &str) -> Option<std::ops::Range<usize>> {
    let start = v.find("://")? + 3;
    let rest = &v[start..];
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let at = authority.rfind('@')?;
    let colon = authority[..at].find(':')?;
    (colon + 1 < at).then(|| start + colon + 1..start + at)
}

pub fn url_password(v: &str) -> Option<&str> {
    url_password_range(v).map(|r| &v[r])
}

fn mask_url(v: &str) -> String {
    match url_password_range(v) {
        Some(r) => format!("{}{}{}", &v[..r.start], token(&v[r.clone()]), &v[r.end..]),
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

/// A command flag name whose value is secret: secret-looking long names,
/// and the conventional short password flag `-p`.
fn is_secret_flag(flag: &str, short: bool) -> bool {
    if short {
        flag == "p"
    } else {
        is_secret_key(flag)
    }
}

/// Values of secret-looking `--flag value` / `--flag=value` / `-p value` args.
pub fn secret_cmd_values(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        let Some(flag) = a.strip_prefix('-') else {
            continue;
        };
        let short = !flag.starts_with('-');
        let flag = flag.trim_start_matches('-');
        match flag.split_once('=') {
            Some((f, v)) if is_secret_flag(f, short) && !v.is_empty() => out.push(v.to_string()),
            None if is_secret_flag(flag, short) => {
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

    /// Register everything secret in a spec: env, labels, log options and
    /// command args.
    pub fn add_spec(&mut self, spec: &super::spec::RunSpec) {
        for (k, v) in &spec.env {
            self.add(k, v);
        }
        for (k, v) in &spec.labels {
            self.add_label(k, v);
        }
        for (k, v) in &spec.log_opts {
            self.add(k, v);
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

/// `--log-opt k=v` / `--log-opt=k=v` values masked by key, in a
/// space-separated parameter string (dockerMan's ExtraParams).
pub fn mask_extra_params(params: &str) -> String {
    let mut next = false;
    params
        .split(' ')
        .map(|w| {
            let out = match (next, w.strip_prefix("--log-opt=")) {
                (true, _) => mask_kv(w),
                (false, Some(kv)) => format!("--log-opt={}", mask_kv(kv)),
                (false, None) => w.to_string(),
            };
            next = w == "--log-opt";
            out
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A `key=value` log option with its value masked by key.
pub fn mask_kv(kv: &str) -> String {
    match kv.split_once('=') {
        Some((k, v)) => format!("{k}={}", mask(k, v)),
        None => kv.to_string(),
    }
}

/// Opening `<Config` followed by whitespace, at or after `from`.
fn find_config(xml: &str, from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(p) = xml[i..].find("<Config") {
        let at = i + p;
        if xml[at + "<Config".len()..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
        {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

/// Mask Variable values (element text and `Default`) in template XML,
/// whoever wrote it: entirely for a secret name or `Mask="true"`, otherwise
/// any URL password inside them. Log options in `<ExtraParams>` are masked
/// by key.
pub fn mask_template_xml(xml: &str) -> String {
    let xml = mask_extra_params_element(xml);
    let mut out = String::with_capacity(xml.len());
    let mut pos = 0;
    while let Some(start) = find_config(&xml, pos) {
        out.push_str(&xml[pos..start]);
        let tail = &xml[start..];
        let Some(open_end) = tail.find('>') else {
            out.push_str(tail);
            return out;
        };
        let open = &tail[..open_end];
        let self_closing = open.ends_with('/');
        let is_var = attr(open, "Type").map(|a| a.1).as_deref() == Some("Variable");
        if !is_var {
            out.push_str(&tail[..=open_end]);
            pos = start + open_end + 1;
            continue;
        }
        let target = attr(open, "Target")
            .or_else(|| attr(open, "Name"))
            .map(|a| a.1);
        let secret = target.as_deref().is_some_and(is_secret_key)
            || attr(open, "Mask").is_some_and(|a| a.1 == "true");
        let hide = |v: &str| if secret { token(v) } else { mask_url(v) };
        match attr(open, "Default") {
            Some((r, d)) if !d.is_empty() => {
                out.push_str(&open[..r.start]);
                out.push_str(&xml_escape(&hide(&d)));
                out.push_str(&open[r.end..]);
            }
            _ => out.push_str(open),
        }
        out.push('>');
        if self_closing {
            pos = start + open_end + 1;
            continue;
        }
        let Some(close) = tail.find("</Config>") else {
            out.push_str(&tail[open_end + 1..]);
            return out;
        };
        let inner = &tail[open_end + 1..close];
        if !inner.is_empty() {
            let value = super::template::xml_unescape(inner);
            out.push_str(&xml_escape(&hide(&value)));
        }
        out.push_str("</Config>");
        pos = start + close + "</Config>".len();
    }
    out.push_str(&xml[pos..]);
    out
}

fn mask_extra_params_element(xml: &str) -> String {
    let (open, close) = ("<ExtraParams>", "</ExtraParams>");
    let (Some(s), Some(e)) = (xml.find(open), xml.find(close)) else {
        return xml.to_string();
    };
    let s = s + open.len();
    if s > e {
        return xml.to_string();
    }
    let inner = super::template::xml_unescape(&xml[s..e]);
    format!(
        "{}{}{}",
        &xml[..s],
        xml_escape(&mask_extra_params(&inner)),
        &xml[e..]
    )
}

/// Byte range (within `open`) and unescaped value of attribute `name`.
fn attr(open: &str, name: &str) -> Option<(std::ops::Range<usize>, String)> {
    let needle = format!("{name}=\"");
    let mut from = 0;
    while let Some(p) = open[from..].find(&needle) {
        let at = from + p;
        if open[..at].ends_with(char::is_whitespace) {
            let s = at + needle.len();
            let e = open[s..].find('"')? + s;
            return Some((s..e, super::template::xml_unescape(&open[s..e])));
        }
        from = at + 1;
    }
    None
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

    #[test]
    fn new_secret_words_and_pw_as_a_word() {
        for k in [
            "ADMIN_PWD",
            "DB_PW",
            "pw",
            "JWT",
            "PASSWORD_SALT",
            "SENTRY_DSN",
            "SLACK_WEBHOOK",
            "SIGNING_K",
            "ENCRYPTION_X",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in ["UPWARD", "PWM_MODE", "PUID"] {
            assert!(!is_secret_key(k), "{k}");
        }
    }

    #[test]
    fn url_password_bounds_the_authority_and_takes_the_last_at() {
        assert_eq!(url_password("https://u:p@ss@h/x"), Some("p@ss"));
        assert_eq!(url_password("https://h/path?u=a:b@c"), None);
        assert_eq!(url_password("https://h#a:b@c"), None);
        assert_eq!(url_password("redis://:pw9@h:6379"), Some("pw9"));
        assert_eq!(url_password("http://u:@h"), None);
        // Masked by position, even when the same text appears earlier.
        let m = mask("X", "pw9 redis://u:pw9@h");
        assert!(m.starts_with("pw9 redis://u:<redacted:"), "{m}");
    }

    #[test]
    fn short_password_flag_is_masked() {
        let args: Vec<String> = ["mysql", "-u", "root", "-p", "s3cret", "-p=x2"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(secret_cmd_values(&args), vec!["s3cret", "x2"]);
    }

    #[test]
    fn log_opts_are_masked_in_params_and_templates() {
        let p = mask_extra_params(
            "--log-driver splunk --log-opt splunk-token=abcd1234 --log-opt=splunk-url=https://u:pw77@h --log-opt max-file=1",
        );
        assert!(!p.contains("abcd1234") && !p.contains("pw77"), "{p}");
        assert!(p.contains("max-file=1"), "{p}");
        let xml = "<ExtraParams>--log-opt splunk-token=abcd1234</ExtraParams>";
        assert!(!mask_template_xml(xml).contains("abcd1234"));
    }

    #[test]
    fn template_masking_honours_mask_attr_and_any_whitespace() {
        let xml = "<Config\n  Name=\"X\" Target=\"OPAQUE\" Default=\"zzz-1\" Type=\"Variable\" Mask=\"true\">zzz-1</Config>";
        let out = mask_template_xml(xml);
        assert!(!out.contains("zzz-1"), "{out}");
        // A Default whose escaped form differs is still found by position.
        let xml = r#"<Config Name="K" Target="API_KEY" Default="a&amp;b" Type="Variable">a&amp;b</Config>"#;
        assert!(!mask_template_xml(xml).contains("a&amp;b"));
        // `XDefault=` is not the Default attribute.
        assert!(
            attr(r#"<Config XDefault="1" Default="2""#, "Default")
                .unwrap()
                .1
                == "2"
        );
    }
}
