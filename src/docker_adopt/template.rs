//! Unraid dockerMan user templates (`my-<name>.xml`): build one from a
//! [`RunSpec`], render it, and patch the `<Icon>` of an existing one.

use super::redact::is_secret_key;
use super::spec::{self, MountKind, RunSpec};

pub const TEMPLATES_DIR: &str = "/boot/config/plugins/dockerMan/templates-user";
pub const DEFAULT_ICON_BASE: &str = "https://gitea.scottkey.me/argyle-labs";
/// Hosts an icon base URL may point at, besides those in [`ICON_HOSTS_ENV`].
pub const DEFAULT_ICON_HOSTS: &[&str] = &["gitea.scottkey.me"];
/// Comma-separated extra icon hosts, set on the orca daemon.
pub const ICON_HOSTS_ENV: &str = "ORCA_UNRAID_ICON_HOSTS";
/// Marks a template orca wrote. An XML comment, which dockerMan ignores.
pub const MANAGED_MARKER: &str = "<!-- managed-by: orca -->";

pub fn template_path(name: &str) -> String {
    format!("{TEMPLATES_DIR}/my-{name}.xml")
}

pub fn backup_path(name: &str, date: &str) -> String {
    format!("{}.bak-{date}", template_path(name))
}

pub fn inspect_backup_path(name: &str, date: &str) -> String {
    format!("{}.inspect-{date}.json", template_path(name))
}

/// An icon base must be https on an allowlisted host, with nothing a
/// template or shell could misread.
pub fn validate_icon_base(base: &str, extra_hosts: &[String]) -> Result<(), String> {
    let bad = || format!("invalid icon_base '{base}'");
    let rest = base
        .strip_prefix("https://")
        .ok_or_else(|| format!("{}: must be https", bad()))?;
    if base
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || "\"'<>`\\&?#".contains(c))
    {
        return Err(format!("{}: contains a forbidden character", bad()));
    }
    let host = rest.split('/').next().unwrap_or("").to_ascii_lowercase();
    let allowed = DEFAULT_ICON_HOSTS
        .iter()
        .map(|h| h.to_string())
        .chain(extra_hosts.iter().map(|h| h.trim().to_ascii_lowercase()))
        .any(|h| !h.is_empty() && h == host);
    if !allowed {
        return Err(format!(
            "{}: host {host:?} is not allowlisted (add it to {ICON_HOSTS_ENV})",
            bad()
        ));
    }
    Ok(())
}

pub fn icon_url(base: &str, repo: &str) -> String {
    format!(
        "{}/{repo}/raw/branch/main/assets/icon-256.png",
        base.trim_end_matches('/')
    )
}

/// Whether `url` is an argyle-labs repo icon under `base`.
pub fn is_orca_icon(base: &str, url: &str) -> bool {
    let prefix = format!("{}/", base.trim_end_matches('/'));
    url.strip_prefix(&prefix)
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(repo, tail)| {
            !repo.is_empty() && tail == "raw/branch/main/assets/icon-256.png"
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKind {
    Port,
    Path,
    Variable,
}

impl ConfigKind {
    fn as_str(self) -> &'static str {
        match self {
            ConfigKind::Port => "Port",
            ConfigKind::Path => "Path",
            ConfigKind::Variable => "Variable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateConfig {
    pub kind: ConfigKind,
    pub name: String,
    pub target: String,
    pub mode: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Template {
    pub name: String,
    pub repository: String,
    pub network: String,
    pub privileged: bool,
    pub icon: String,
    pub extra_params: String,
    pub post_args: String,
    pub configs: Vec<TemplateConfig>,
}

impl Template {
    /// Map a spec onto template fields. Ports with a host IP and binds with
    /// non-default propagation have no Config form, so they go to ExtraParams.
    pub fn from_spec(spec: &RunSpec, icon: &str) -> Self {
        let mut configs = Vec::new();
        let mut extra: Vec<String> = Vec::new();

        for p in &spec.ports {
            let parts: Vec<&str> = p.split(':').collect();
            match parts.as_slice() {
                [host, cport] => {
                    let (target, proto) = cport.split_once('/').unwrap_or((cport, "tcp"));
                    configs.push(TemplateConfig {
                        kind: ConfigKind::Port,
                        name: format!("Port {target}/{proto}"),
                        target: target.to_string(),
                        mode: proto.to_string(),
                        value: host.to_string(),
                    });
                }
                _ => extra.push(format!("-p {}", spec::shell_quote(p))),
            }
        }

        for m in &spec.mounts {
            if m.kind == MountKind::Bind && m.propagation.is_some() {
                let mut s = format!("type=bind,src={},dst={}", m.source, m.target);
                if m.read_only {
                    s.push_str(",readonly");
                }
                if let Some(p) = &m.propagation {
                    s.push_str(&format!(",bind-propagation={p}"));
                }
                extra.push(format!("--mount {}", spec::shell_quote(&s)));
                continue;
            }
            configs.push(TemplateConfig {
                kind: ConfigKind::Path,
                name: format!("Path {}", m.target),
                target: m.target.clone(),
                mode: if m.read_only { "ro" } else { "rw" }.to_string(),
                value: m.source.clone(),
            });
        }

        // dockerMan injects `TZ=""` before the template's variables; an explicit
        // TZ variable comes later and wins.
        if !spec.tz.is_empty() {
            configs.push(TemplateConfig {
                kind: ConfigKind::Variable,
                name: "TZ".to_string(),
                target: "TZ".to_string(),
                mode: String::new(),
                value: spec.tz.clone(),
            });
        }
        for (k, v) in &spec.env {
            configs.push(TemplateConfig {
                kind: ConfigKind::Variable,
                name: k.clone(),
                target: k.clone(),
                mode: String::new(),
                value: v.clone(),
            });
        }

        if let Some(h) = &spec.hostname {
            extra.push(format!("--hostname {}", spec::shell_quote(h)));
        }
        for (path, opts) in &spec.tmpfs {
            let v = if opts.is_empty() {
                path.clone()
            } else {
                format!("{path}:{opts}")
            };
            extra.push(format!("--tmpfs {}", spec::shell_quote(&v)));
        }
        if spec.log_driver != spec::DEFAULT_LOG_DRIVER {
            extra.push(format!(
                "--log-driver {}",
                spec::shell_quote(&spec.log_driver)
            ));
        }
        for (k, v) in &spec.log_opts {
            extra.push(format!(
                "--log-opt {}",
                spec::shell_quote(&format!("{k}={v}"))
            ));
        }
        if let Some(g) = &spec.gpus {
            extra.push(format!("--gpus {}", spec::shell_quote(g)));
        }
        if let Some(r) = &spec.restart {
            extra.push(format!("--restart {}", spec::shell_quote(r)));
        }
        // dockerMan always adds its own --pids-limit first; a later one wins.
        if let Some(n) = spec.pids_limit.filter(|n| *n != spec::UNRAID_PIDS_LIMIT) {
            extra.push(format!("--pids-limit {n}"));
        }
        for (k, v) in &spec.labels {
            extra.push(format!(
                "--label {}",
                spec::shell_quote(&format!("{k}={v}"))
            ));
        }

        Template {
            name: spec.name.clone(),
            repository: spec.image.clone(),
            network: spec.network.clone(),
            privileged: spec.privileged,
            icon: icon.to_string(),
            extra_params: extra.join(" "),
            post_args: spec
                .cmd
                .iter()
                .map(|w| spec::shell_quote(w))
                .collect::<Vec<_>>()
                .join(" "),
            configs,
        }
    }

    pub fn render(&self) -> String {
        let mut x = String::from("<?xml version=\"1.0\"?>\n<Container version=\"2\">\n");
        x.push_str(&format!("  {MANAGED_MARKER}\n"));
        let el = |x: &mut String, tag: &str, val: &str| {
            if val.is_empty() {
                x.push_str(&format!("  <{tag}/>\n"));
            } else {
                x.push_str(&format!("  <{tag}>{}</{tag}>\n", xml_escape(val)));
            }
        };
        el(&mut x, "Name", &self.name);
        el(&mut x, "Repository", &self.repository);
        el(&mut x, "Registry", "");
        el(&mut x, "Network", &self.network);
        el(
            &mut x,
            "Privileged",
            if self.privileged { "true" } else { "false" },
        );
        el(&mut x, "Support", "");
        el(&mut x, "Project", "");
        el(&mut x, "Overview", "");
        el(&mut x, "Category", "");
        el(&mut x, "WebUI", "");
        el(&mut x, "Icon", &self.icon);
        // dockerMan HTML-decodes these two fields once more after XML parsing.
        el(
            &mut x,
            "ExtraParams",
            &self.extra_params.replace('&', "&amp;"),
        );
        el(&mut x, "PostArgs", &self.post_args.replace('&', "&amp;"));
        for c in &self.configs {
            x.push_str(&format!(
                "  <Config Name=\"{}\" Target=\"{}\" Default=\"{}\" Mode=\"{}\" Description=\"\" \
                 Type=\"{}\" Display=\"always\" Required=\"false\" Mask=\"{}\">{}</Config>\n",
                xml_escape(&c.name),
                xml_escape(&c.target),
                xml_escape(&c.value),
                xml_escape(&c.mode),
                c.kind.as_str(),
                c.kind == ConfigKind::Variable && is_secret_key(&c.target),
                xml_escape(&c.value),
            ));
        }
        x.push_str("</Container>\n");
        x
    }
}

pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

pub fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The text of the first `<Name>` element, if any.
pub fn extract_name(xml: &str) -> Option<String> {
    let s = xml.find("<Name>")? + "<Name>".len();
    let e = xml[s..].find("</Name>")? + s;
    Some(xml_unescape(xml[s..e].trim()))
}

/// Byte range of the `<Icon>` element (`<Icon>…</Icon>` or `<Icon/>`).
fn icon_span(xml: &str) -> Option<(usize, usize)> {
    if let Some(start) = xml.find("<Icon/>") {
        return Some((start, start + "<Icon/>".len()));
    }
    let start = xml.find("<Icon>")?;
    let end = xml[start..].find("</Icon>")? + start + "</Icon>".len();
    Some((start, end))
}

/// The `<Icon>` text of a template, if any.
pub fn extract_icon(xml: &str) -> Option<String> {
    let (s, e) = icon_span(xml)?;
    let inner = xml[s..e]
        .strip_prefix("<Icon>")?
        .strip_suffix("</Icon>")?
        .trim();
    (!inner.is_empty()).then(|| xml_unescape(inner))
}

/// Replace (or add) `<Icon>` and ensure the managed marker is present.
pub fn set_icon(xml: &str, url: &str) -> Result<String, String> {
    let element = format!("<Icon>{}</Icon>", xml_escape(url));
    let mut out = match icon_span(xml) {
        Some((s, e)) => format!("{}{element}{}", &xml[..s], &xml[e..]),
        None => {
            let close = xml
                .rfind("</Container>")
                .ok_or_else(|| "template has no </Container>".to_string())?;
            format!("{}  {element}\n{}", &xml[..close], &xml[close..])
        }
    };
    if !out.contains(MANAGED_MARKER) {
        let open = out
            .find("<Container")
            .and_then(|s| out[s..].find('>').map(|e| s + e + 1))
            .ok_or_else(|| "template has no <Container> element".to_string())?;
        out.insert_str(open, &format!("\n  {MANAGED_MARKER}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_url_and_detection() {
        let u = icon_url("https://gitea.scottkey.me/argyle-labs/", "pbs");
        assert_eq!(
            u,
            "https://gitea.scottkey.me/argyle-labs/pbs/raw/branch/main/assets/icon-256.png"
        );
        assert!(is_orca_icon(DEFAULT_ICON_BASE, &u));
        assert!(!is_orca_icon(
            DEFAULT_ICON_BASE,
            "https://raw.githubusercontent.com/x/y/icon.png"
        ));
    }

    #[test]
    fn escaping_round_trips() {
        let s = r#"a&b<c>"d"'e"#;
        assert_eq!(xml_escape(s), "a&amp;b&lt;c&gt;&quot;d&quot;&apos;e");
        assert_eq!(xml_unescape(&xml_escape(s)), s);
    }

    #[test]
    fn set_icon_replaces_existing_and_marks() {
        let xml = "<?xml version=\"1.0\"?>\n<Container version=\"2\">\n  <Name>x</Name>\n  <Icon>old</Icon>\n</Container>\n";
        let out = set_icon(xml, "https://h/a&b.png").unwrap();
        assert!(out.contains("<Icon>https://h/a&amp;b.png</Icon>"));
        assert!(!out.contains("old"));
        assert!(out.contains(MANAGED_MARKER));
        assert_eq!(extract_icon(&out).as_deref(), Some("https://h/a&b.png"));
        assert_eq!(set_icon(&out, "https://h/a&b.png").unwrap(), out);
    }

    #[test]
    fn set_icon_adds_missing_element() {
        let xml = "<Container version=\"2\"><Name>x</Name><Icon/></Container>";
        let out = set_icon(xml, "u").unwrap();
        assert!(out.contains("<Icon>u</Icon>"));
        let xml = "<Container version=\"2\"><Name>x</Name></Container>";
        let out = set_icon(xml, "u").unwrap();
        assert_eq!(extract_icon(&out).as_deref(), Some("u"));
    }
}
