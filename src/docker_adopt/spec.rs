//! The comparable shape of a container — [`RunSpec`] — built either from a live
//! `docker inspect` or by parsing the `docker create` command Unraid renders
//! from a template, plus the diff between two of them.

use std::collections::{BTreeMap, BTreeSet};

use super::redact;

/// Env Unraid's renderer injects into every container (`TZ` is modelled
/// separately as [`RunSpec::tz`]).
const UNRAID_ENV: &[&str] = &["HOST_OS", "HOST_HOSTNAME", "HOST_CONTAINERNAME"];
/// Label prefix Unraid's renderer stamps (`managed`, `webui`, `icon`, …).
const UNRAID_LABEL_PREFIX: &str = "net.unraid.docker.";
pub const DEFAULT_LOG_DRIVER: &str = "json-file";
/// `--pids-limit` dockerMan adds to every container it renders.
pub const UNRAID_PIDS_LIMIT: i64 = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MountKind {
    Bind,
    Volume,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MountSpec {
    pub kind: MountKind,
    /// Host path for a bind, volume name for a volume.
    pub source: String,
    pub target: String,
    pub read_only: bool,
    /// Bind propagation when not docker's default (`rprivate`).
    pub propagation: Option<String>,
}

impl std::fmt::Display for MountSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.kind {
            MountKind::Bind => "bind",
            MountKind::Volume => "volume",
        };
        write!(
            f,
            "{kind} {} -> {} ({})",
            self.source,
            self.target,
            if self.read_only { "ro" } else { "rw" }
        )?;
        if let Some(p) = &self.propagation {
            write!(f, " propagation={p}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunSpec {
    pub name: String,
    pub image: String,
    pub network: String,
    pub privileged: bool,
    pub hostname: Option<String>,
    /// `hostname` is the container's own short id — docker's default.
    pub hostname_is_default: bool,
    /// `[host_ip:]host_port:container_port/proto`.
    pub ports: BTreeSet<String>,
    /// Operator-set env, excluding `TZ`.
    pub env: BTreeMap<String, String>,
    /// Effective `TZ` ("" when unset).
    pub tz: String,
    pub mounts: BTreeSet<MountSpec>,
    pub tmpfs: BTreeMap<String, String>,
    pub log_driver: String,
    pub log_opts: BTreeMap<String, String>,
    pub gpus: Option<String>,
    pub restart: Option<String>,
    /// `None` = unlimited.
    pub pids_limit: Option<i64>,
    pub labels: BTreeMap<String, String>,
    pub cmd: Vec<String>,
    /// Flags in a rendered command this module does not model.
    pub other: Vec<String>,
}

impl RunSpec {
    /// Drop what Unraid injects and canonicalize spellings, so a live spec and
    /// a rendered one compare equal when they describe the same container.
    pub fn normalized(mut self) -> Self {
        self.image = normalize_image(&self.image);
        for k in UNRAID_ENV {
            self.env.remove(*k);
        }
        if let Some(tz) = self.env.remove("TZ") {
            self.tz = tz;
        }
        self.labels
            .retain(|k, _| !k.starts_with(UNRAID_LABEL_PREFIX));
        if self.network == "default" {
            self.network = "bridge".to_string();
        }
        self
    }

    /// Drop env entries the image provides with the same value.
    pub fn without_baked_env(mut self, baked: &BTreeSet<String>) -> Self {
        self.env.retain(|k, v| !baked.contains(&format!("{k}={v}")));
        self
    }
}

/// `nginx` → `nginx:latest`; `docker.io/library/x:1` → `x:1`.
pub fn normalize_image(image: &str) -> String {
    let mut s = image.trim();
    for p in ["docker.io/", "index.docker.io/"] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest;
        }
    }
    let s = s.strip_prefix("library/").unwrap_or(s);
    let last = s.rsplit('/').next().unwrap_or(s);
    if s.contains('@') || last.contains(':') {
        s.to_string()
    } else {
        format!("{s}:latest")
    }
}

/// Canonical port key. A bare or wildcard host IP is dropped; IPv6 host IPs
/// are bracketed.
pub fn port_key(host_ip: &str, host_port: &str, container_port: &str) -> String {
    let cport = if container_port.contains('/') {
        container_port.to_string()
    } else {
        format!("{container_port}/tcp")
    };
    match host_ip.trim_matches(['[', ']']) {
        "" | "0.0.0.0" | "::" => format!("{host_port}:{cport}"),
        ip if ip.contains(':') => format!("[{ip}]:{host_port}:{cport}"),
        ip => format!("{ip}:{host_port}:{cport}"),
    }
}

/// `None` for docker's default bind propagation.
pub fn non_default_propagation(p: &str) -> Option<String> {
    match p {
        "" | "rprivate" => None,
        other => Some(other.to_string()),
    }
}

/// Characters that, unquoted, would make the shell do more than split words.
const UNQUOTED_META: &[char] = &[
    '$', '`', ';', '|', '&', '<', '>', '(', ')', '\n', '#', '*', '?', '[', '~',
];

/// Split a POSIX shell command line into words. Single quotes are literal;
/// double quotes honour `\"`/`\\`; adjacent quoted runs join. Anything the
/// shell would expand or act on (unquoted metacharacters, `$` or a backtick
/// inside double quotes) is an error, so the fidelity gate fails closed
/// rather than comparing against a command the shell would rewrite.
pub fn shell_split(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err("unterminated single quote".to_string()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(ch @ ('"' | '\\')) => cur.push(ch),
                            Some(ch @ ('$' | '`')) => {
                                return Err(format!("escaped {ch:?} inside double quotes"));
                            }
                            Some(ch) => {
                                cur.push('\\');
                                cur.push(ch);
                            }
                            None => return Err("unterminated double quote".to_string()),
                        },
                        Some(ch @ ('$' | '`')) => {
                            return Err(format!("{ch:?} inside double quotes"));
                        }
                        Some(ch) => cur.push(ch),
                        None => return Err("unterminated double quote".to_string()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some('\n') | None => return Err("trailing backslash".to_string()),
                    Some(ch) => cur.push(ch),
                }
            }
            c if UNQUOTED_META.contains(&c) => {
                return Err(format!("unquoted shell metacharacter {c:?}"));
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

/// Quote one word for a POSIX shell; safe words are left bare.
pub fn shell_quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:=,@%+-".contains(&b));
    if safe {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// `docker create` flags that take no value.
const BOOL_FLAGS: &[&str] = &[
    "-d",
    "--detach",
    "-i",
    "--interactive",
    "-t",
    "--tty",
    "--rm",
    "--init",
    "--read-only",
];

/// Parse the `docker create|run …` command Unraid renders into a [`RunSpec`].
/// Words before the `create`/`run` subcommand (the docker wrapper path) are
/// skipped; the first non-flag word is the image and the rest is its command.
pub fn parse_command(cmd: &str) -> Result<RunSpec, String> {
    let words = shell_split(cmd.trim())?;
    let start = words
        .iter()
        .position(|w| w == "create" || w == "run")
        .ok_or_else(|| "rendered command has no `docker create`/`docker run`".to_string())?;
    let mut spec = RunSpec {
        network: "bridge".to_string(),
        log_driver: DEFAULT_LOG_DRIVER.to_string(),
        ..RunSpec::default()
    };
    let mut it = words[start + 1..].iter();
    while let Some(w) = it.next() {
        if !w.starts_with('-') {
            spec.image = w.clone();
            spec.cmd = it.cloned().collect();
            break;
        }
        let (flag, inline) = match w.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (w.clone(), None),
        };
        if flag == "--privileged" {
            spec.privileged = inline.as_deref().is_none_or(|v| v == "true");
            continue;
        }
        if BOOL_FLAGS.contains(&flag.as_str()) {
            spec.other.push(w.clone());
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None => it
                .next()
                .cloned()
                .ok_or_else(|| format!("flag {flag} has no value"))?,
        };
        match flag.as_str() {
            "--name" => spec.name = value,
            "--net" | "--network" => spec.network = value,
            "-h" | "--hostname" => spec.hostname = Some(value),
            "-e" | "--env" => {
                let (k, v) = value.split_once('=').unwrap_or((value.as_str(), ""));
                spec.env.insert(k.to_string(), v.to_string());
            }
            "-l" | "--label" => {
                let (k, v) = value.split_once('=').unwrap_or((value.as_str(), ""));
                spec.labels.insert(k.to_string(), v.to_string());
            }
            "-p" | "--publish" => {
                spec.ports.insert(parse_publish(&value)?);
            }
            "-v" | "--volume" => {
                spec.mounts.insert(parse_volume(&value)?);
            }
            "--mount" => {
                spec.mounts.insert(parse_mount(&value)?);
            }
            "--tmpfs" => {
                let (path, opts) = value.split_once(':').unwrap_or((value.as_str(), ""));
                spec.tmpfs.insert(path.to_string(), opts.to_string());
            }
            "--log-driver" => spec.log_driver = value,
            "--log-opt" => {
                let (k, v) = value.split_once('=').unwrap_or((value.as_str(), ""));
                spec.log_opts.insert(k.to_string(), v.to_string());
            }
            "--gpus" => spec.gpus = Some(value.trim_matches('"').to_string()),
            "--restart" => {
                spec.restart = (value != "no").then_some(value);
            }
            "--pids-limit" => {
                let n: i64 = value
                    .parse()
                    .map_err(|_| format!("bad --pids-limit {value:?}"))?;
                spec.pids_limit = (n > 0).then_some(n);
            }
            _ => spec.other.push(format!("{flag}={value}")),
        }
    }
    if spec.image.is_empty() {
        return Err("rendered command names no image".to_string());
    }
    Ok(spec.normalized())
}

/// `[ip:]host:container[/proto]` → [`port_key`]. An IPv6 host IP is bracketed.
fn parse_publish(v: &str) -> Result<String, String> {
    if let Some(rest) = v.strip_prefix('[') {
        let (ip, rest) = rest
            .split_once("]:")
            .ok_or_else(|| format!("unsupported port publish {v:?}"))?;
        let (hport, cport) = rest
            .split_once(':')
            .ok_or_else(|| format!("unsupported port publish {v:?}"))?;
        return Ok(port_key(ip, hport, cport));
    }
    let parts: Vec<&str> = v.split(':').collect();
    match parts.as_slice() {
        [hport, cport] => Ok(port_key("", hport, cport)),
        [ip, hport, cport] => Ok(port_key(ip, hport, cport)),
        _ => Err(format!("unsupported port publish {v:?}")),
    }
}

/// `src:dst[:opts]` where `opts` is a comma list of `ro`/`rw`/propagation.
fn parse_volume(v: &str) -> Result<MountSpec, String> {
    let parts: Vec<&str> = v.split(':').collect();
    let (src, dst, opts) = match parts.as_slice() {
        [src, dst] => (*src, *dst, ""),
        [src, dst, opts] => (*src, *dst, *opts),
        _ => return Err(format!("unsupported volume spec {v:?}")),
    };
    let mut read_only = false;
    let mut propagation = None;
    for o in opts.split(',').filter(|o| !o.is_empty()) {
        match o {
            "ro" => read_only = true,
            "rw" | "z" | "Z" => {}
            "rprivate" | "private" | "rslave" | "slave" | "rshared" | "shared" => {
                propagation = non_default_propagation(o)
            }
            other => return Err(format!("unsupported volume option {other:?}")),
        }
    }
    let kind = if src.starts_with('/') {
        MountKind::Bind
    } else {
        MountKind::Volume
    };
    if kind == MountKind::Volume {
        propagation = None;
    }
    Ok(MountSpec {
        kind,
        source: src.to_string(),
        target: dst.to_string(),
        read_only,
        propagation,
    })
}

/// `--mount type=…,src=…,dst=…[,readonly][,bind-propagation=…]`.
fn parse_mount(v: &str) -> Result<MountSpec, String> {
    let mut kind = None;
    let mut source = String::new();
    let mut target = String::new();
    let mut read_only = false;
    let mut propagation = None;
    for field in v.split(',') {
        let (k, val) = field.split_once('=').unwrap_or((field, ""));
        match k {
            "type" => {
                kind = Some(match val {
                    "bind" => MountKind::Bind,
                    "volume" => MountKind::Volume,
                    other => return Err(format!("unsupported --mount type {other:?}")),
                })
            }
            "src" | "source" => source = val.to_string(),
            "dst" | "destination" | "target" => target = val.to_string(),
            "readonly" | "ro" => read_only = val.is_empty() || val == "true" || val == "1",
            "bind-propagation" => propagation = non_default_propagation(val),
            other => return Err(format!("unsupported --mount option {other:?}")),
        }
    }
    let kind = kind.unwrap_or(MountKind::Volume);
    if kind == MountKind::Volume {
        propagation = None;
    }
    Ok(MountSpec {
        kind,
        source,
        target,
        read_only,
        propagation,
    })
}

/// One difference between two specs. `intended` differences are reported but
/// do not block: they are what moving under dockerMan means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    pub msg: String,
    pub intended: bool,
}

fn blocking(msg: String) -> Delta {
    Delta {
        msg,
        intended: false,
    }
}

fn diff_map(
    what: &str,
    want: &BTreeMap<String, String>,
    got: &BTreeMap<String, String>,
    show: fn(&str, &str) -> String,
    out: &mut Vec<Delta>,
) {
    for (k, v) in want {
        match got.get(k) {
            None => out.push(blocking(format!(
                "{what} {k}: missing from rendered (live {:?})",
                show(k, v)
            ))),
            Some(g) if g != v => out.push(blocking(format!(
                "{what} {k}: live {:?}, rendered {:?}",
                show(k, v),
                show(k, g)
            ))),
            _ => {}
        }
    }
    for (k, g) in got {
        if !want.contains_key(k) {
            out.push(blocking(format!(
                "{what} {k}: only in rendered ({:?})",
                show(k, g)
            )));
        }
    }
}

fn diff_set<T: Ord + std::fmt::Display>(
    what: &str,
    want: &BTreeSet<T>,
    got: &BTreeSet<T>,
    out: &mut Vec<Delta>,
) {
    for w in want.difference(got) {
        out.push(blocking(format!("{what} {w}: missing from rendered")));
    }
    for g in got.difference(want) {
        out.push(blocking(format!("{what} {g}: only in rendered")));
    }
}

fn diff_value<T: PartialEq + std::fmt::Debug>(what: &str, want: &T, got: &T, out: &mut Vec<Delta>) {
    if want != got {
        out.push(blocking(format!("{what}: live {want:?}, rendered {got:?}")));
    }
}

/// Which verb a diff serves. Only `set_icon` re-renders a template someone
/// else wrote, where a missing restart policy is the template's existing
/// state; `adopt` writes the template itself and must keep the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    Adopt,
    SetIcon,
}

fn plain(_: &str, v: &str) -> String {
    v.to_string()
}

/// Every difference between the spec a container has or should have (`want`)
/// and the one Unraid would create (`got`). Secret values are masked.
pub fn diff(want: &RunSpec, got: &RunSpec, mode: DiffMode) -> Vec<Delta> {
    let mut out = Vec::new();
    diff_value("name", &want.name, &got.name, &mut out);
    diff_value("image", &want.image, &got.image, &mut out);
    diff_value("network", &want.network, &got.network, &mut out);
    diff_value("privileged", &want.privileged, &got.privileged, &mut out);
    match (&want.hostname, &got.hostname) {
        (a, b) if a == b => {}
        (Some(h), None) if want.hostname_is_default => out.push(Delta {
            msg: format!("hostname {h} (docker's default) becomes the new container's id"),
            intended: true,
        }),
        (None, Some(_)) if got.hostname_is_default => {}
        (a, b) => out.push(blocking(format!("hostname: live {a:?}, rendered {b:?}"))),
    }
    diff_set("port", &want.ports, &got.ports, &mut out);
    diff_map("env", &want.env, &got.env, redact::mask, &mut out);
    if want.tz != got.tz {
        out.push(blocking(format!(
            "TZ: live {:?}, rendered {:?}",
            want.tz, got.tz
        )));
    }
    diff_set("mount", &want.mounts, &got.mounts, &mut out);
    diff_map("tmpfs", &want.tmpfs, &got.tmpfs, plain, &mut out);
    diff_value("log driver", &want.log_driver, &got.log_driver, &mut out);
    diff_map("log-opt", &want.log_opts, &got.log_opts, plain, &mut out);
    diff_value("gpus", &want.gpus, &got.gpus, &mut out);
    match (&want.restart, &got.restart) {
        (a, b) if a == b => {}
        (Some(r), None) if mode == DiffMode::SetIcon => out.push(Delta {
            msg: format!("restart policy {r} dropped; Unraid autostart starts it with the array"),
            intended: true,
        }),
        (a, b) => out.push(blocking(format!("restart: live {a:?}, rendered {b:?}"))),
    }
    match (want.pids_limit, got.pids_limit) {
        (a, b) if a == b => {}
        (None, Some(UNRAID_PIDS_LIMIT)) => out.push(Delta {
            msg: format!("pids-limit unlimited -> {UNRAID_PIDS_LIMIT} (dockerMan default)"),
            intended: true,
        }),
        (a, b) => out.push(blocking(format!("pids-limit: live {a:?}, rendered {b:?}"))),
    }
    diff_map(
        "label",
        &want.labels,
        &got.labels,
        redact::mask_label,
        &mut out,
    );
    if want.cmd != got.cmd {
        out.push(blocking(format!(
            "command: live {:?}, rendered {:?}",
            redact::mask_cmd(&want.cmd),
            redact::mask_cmd(&got.cmd)
        )));
    }
    for o in &got.other {
        out.push(blocking(format!(
            "unmodelled flag in rendered command: {o}"
        )));
    }
    out
}

/// A `docker run` reproducing `spec`, for recovery instructions. Secret env
/// values are masked; the full original is in the saved inspect JSON.
pub fn docker_run_command(spec: &RunSpec) -> String {
    let mut w: Vec<String> = vec![
        "docker".into(),
        "run".into(),
        "--detach".into(),
        format!("--name={}", spec.name),
        format!("--network={}", spec.network),
    ];
    if spec.privileged {
        w.push("--privileged".into());
    }
    if let Some(h) = &spec.hostname {
        w.push(format!("--hostname={h}"));
    }
    for p in &spec.ports {
        w.push(format!("--publish={p}"));
    }
    if !spec.tz.is_empty() {
        w.push(format!("--env=TZ={}", spec.tz));
    }
    for (k, v) in &spec.env {
        w.push(format!("--env={k}={}", redact::mask(k, v)));
    }
    for m in &spec.mounts {
        let mut s = format!(
            "--mount=type={},src={},dst={}",
            if m.kind == MountKind::Bind {
                "bind"
            } else {
                "volume"
            },
            m.source,
            m.target
        );
        if m.read_only {
            s.push_str(",readonly");
        }
        if let Some(p) = &m.propagation {
            s.push_str(&format!(",bind-propagation={p}"));
        }
        w.push(s);
    }
    for (p, o) in &spec.tmpfs {
        w.push(if o.is_empty() {
            format!("--tmpfs={p}")
        } else {
            format!("--tmpfs={p}:{o}")
        });
    }
    if spec.log_driver != DEFAULT_LOG_DRIVER {
        w.push(format!("--log-driver={}", spec.log_driver));
    }
    for (k, v) in &spec.log_opts {
        w.push(format!("--log-opt={k}={v}"));
    }
    if let Some(g) = &spec.gpus {
        w.push(format!("--gpus={g}"));
    }
    if let Some(r) = &spec.restart {
        w.push(format!("--restart={r}"));
    }
    if let Some(n) = spec.pids_limit {
        w.push(format!("--pids-limit={n}"));
    }
    for (k, v) in &spec.labels {
        w.push(format!("--label={k}={}", redact::mask_label(k, v)));
    }
    w.push(spec.image.clone());
    w.extend(redact::mask_cmd(&spec.cmd));
    w.iter()
        .map(|x| shell_quote(x))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_handles_unraid_quoting() {
        let w = shell_split(
            r#"docker create --name='pbs' -e 'PUID'='99' -e TZ="" -l a='it'\''s' -l w='http://[IP]:[PORT:80]/' "x\"y""#,
        )
        .unwrap();
        assert_eq!(
            w,
            vec![
                "docker",
                "create",
                "--name=pbs",
                "-e",
                "PUID=99",
                "-e",
                "TZ=",
                "-l",
                "a=it's",
                "-l",
                "w=http://[IP]:[PORT:80]/",
                "x\"y"
            ]
        );
        assert!(shell_split("'open").is_err());
    }

    #[test]
    fn shell_split_fails_closed_on_expansion() {
        for bad in [
            "a $HOME",
            "a `id`",
            "a; b",
            "a | b",
            "a && b",
            "a > f",
            "a (b)",
            "a\nb",
            "a #c",
            "a *",
            "a ?",
            "a [x]",
            "~/x",
            r#"a "$x""#,
            r#"a "`id`""#,
        ] {
            assert!(shell_split(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn shell_quote_round_trips() {
        for w in ["plain", "with space", "it's", "a&b<c>\"d\" $x `y`", ""] {
            let q = shell_quote(w);
            assert_eq!(shell_split(&q).unwrap(), vec![w.to_string()], "{q}");
        }
        assert_eq!(shell_quote("--hostname=pbs"), "--hostname=pbs");
    }

    #[test]
    fn normalize_image_canonicalizes_hub_refs() {
        assert_eq!(normalize_image("nginx"), "nginx:latest");
        assert_eq!(normalize_image("docker.io/library/nginx:1"), "nginx:1");
        assert_eq!(normalize_image("ghcr.io/x/y:2.0"), "ghcr.io/x/y:2.0");
        assert_eq!(normalize_image("reg:5000/x"), "reg:5000/x:latest");
    }

    #[test]
    fn parse_volume_and_mount_forms() {
        let v = parse_volume("/mnt/user/a:/a:ro,rslave").unwrap();
        assert_eq!(v.kind, MountKind::Bind);
        assert!(v.read_only);
        assert_eq!(v.propagation.as_deref(), Some("rslave"));
        let n = parse_volume("cfg:/etc/x:rw").unwrap();
        assert_eq!(n.kind, MountKind::Volume);
        assert!(parse_volume("cfg:/etc/x:nocopy").is_err());
        let m = parse_mount("type=bind,src=/a,dst=/b,bind-propagation=rslave").unwrap();
        assert_eq!(m.propagation.as_deref(), Some("rslave"));
        assert!(!m.read_only);
        assert!(parse_mount("type=tmpfs,dst=/x").is_err());
    }

    #[test]
    fn parse_publish_forms() {
        assert_eq!(parse_publish("10300:9000/tcp").unwrap(), "10300:9000/tcp");
        assert_eq!(parse_publish("53:53/udp").unwrap(), "53:53/udp");
        assert_eq!(
            parse_publish("127.0.0.1:80:8080").unwrap(),
            "127.0.0.1:80:8080/tcp"
        );
        assert_eq!(
            parse_publish("[::1]:80:8080/tcp").unwrap(),
            "[::1]:80:8080/tcp"
        );
        assert_eq!(port_key("::1", "80", "8080/tcp"), "[::1]:80:8080/tcp");
    }

    #[test]
    fn unknown_rendered_flags_surface_in_diff() {
        let got = parse_command("docker create --name=x --cpuset-cpus=1 img").unwrap();
        let want = RunSpec {
            name: "x".into(),
            image: "img:latest".into(),
            network: "bridge".into(),
            log_driver: DEFAULT_LOG_DRIVER.into(),
            ..RunSpec::default()
        };
        assert_eq!(
            diff(&want, &got, DiffMode::Adopt),
            vec![blocking(
                "unmodelled flag in rendered command: --cpuset-cpus=1".into()
            )]
        );
    }

    #[test]
    fn last_tz_wins_and_secrets_are_masked_in_diff() {
        let got = parse_command(
            r#"docker create --name=x -e TZ="" -e 'TZ'='America/Denver' -e 'API_KEY'='abc123' img"#,
        )
        .unwrap();
        assert_eq!(got.tz, "America/Denver");
        let want = RunSpec {
            name: "x".into(),
            image: "img:latest".into(),
            network: "bridge".into(),
            log_driver: DEFAULT_LOG_DRIVER.into(),
            tz: "America/Denver".into(),
            ..RunSpec::default()
        };
        let d = diff(&want, &got, DiffMode::Adopt);
        assert_eq!(d.len(), 1);
        assert!(!d[0].msg.contains("abc123"), "{d:?}");
        assert!(d[0].msg.contains("<redacted:"), "{d:?}");
    }

    #[test]
    fn recovery_command_masks_secrets_and_parses_back() {
        let mut s = RunSpec {
            name: "x".into(),
            image: "img:1".into(),
            network: "bridge".into(),
            log_driver: DEFAULT_LOG_DRIVER.into(),
            ..RunSpec::default()
        };
        s.env.insert("TOKEN".into(), "hunter22".into());
        s.env.insert("PUID".into(), "99".into());
        let cmd = docker_run_command(&s);
        assert!(!cmd.contains("hunter22"), "{cmd}");
        assert!(parse_command(&cmd).is_ok(), "{cmd}");
    }
}
