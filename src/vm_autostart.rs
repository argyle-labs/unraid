//! `unraid.vm.autostart` — turn a libvirt VM's autostart on or off.
//!
//! The Unraid GraphQL API has no autostart mutation, so this runs
//! `virsh autostart`, which updates libvirtd's in-memory state as well as the
//! `autostart/` link. The state is read over libvirt's read-only socket; the
//! change runs as root through the privileged seam as
//! [`PrivilegedOp::SetVmAutostart`]. Dry-run by default, admin required for
//! both (see [`crate::authz`]).

use std::future::Future;

use plugin_toolkit::prelude::*;

use crate::authz::require_admin;
use crate::docker_adopt::host;
use crate::docker_adopt::privileged::{self, PrivilegedOp};

/// libvirt's official CLI; the C API would mean linking libvirt.
pub(crate) const VIRSH: &str = "/usr/bin/virsh";

const MAX_VM_NAME: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    NoOp,
    Enable,
    Disable,
}

fn is_uuid_shaped(s: &str) -> bool {
    let hex: String = s.chars().filter(|&c| c != '-').collect();
    hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// VM names become file names and virsh arguments: reject separators,
/// traversal, control characters and overlong names. virsh resolves
/// `--domain` as an id, then a uuid, before a name, so all-digit and
/// uuid-shaped names could select a different domain.
pub(crate) fn validate_vm_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.bytes().all(|b| b.is_ascii_digit())
        || is_uuid_shaped(name)
        || name.len() > MAX_VM_NAME
        || name.contains('/')
        || name.chars().any(char::is_control)
        || name == "."
        || name == ".."
    {
        bail!("invalid VM name '{}'", name.escape_debug());
    }
    Ok(())
}

/// The `Autostart:` field of `virsh dominfo`.
pub(crate) fn parse_autostart(dominfo: &str) -> Result<bool> {
    let value = dominfo
        .lines()
        .find_map(|l| l.strip_prefix("Autostart:"))
        .map(str::trim)
        .ok_or_else(|| anyhow!("virsh dominfo has no Autostart field"))?;
    match value {
        "enable" => Ok(true),
        "disable" => Ok(false),
        other => bail!("unexpected Autostart value '{other}'"),
    }
}

pub(crate) async fn plan<F, Fut>(virsh: &F, name: &str, enabled: bool) -> Result<Change>
where
    F: Fn(Vec<String>) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    validate_vm_name(name)?;
    let info = virsh(vec![
        "-r".into(),
        "dominfo".into(),
        "--domain".into(),
        name.into(),
    ])
    .await?;
    Ok(match (parse_autostart(&info)?, enabled) {
        (false, true) => Change::Enable,
        (true, false) => Change::Disable,
        _ => Change::NoOp,
    })
}

/// Re-reads the state and applies it; run as root.
pub(crate) async fn set<F, Fut>(virsh: &F, name: &str, enabled: bool) -> Result<Change>
where
    F: Fn(Vec<String>) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let change = plan(virsh, name, enabled).await?;
    if change != Change::NoOp {
        let mut args = vec!["autostart".into(), "--domain".into(), name.into()];
        if change == Change::Disable {
            args.push("--disable".into());
        }
        virsh(args).await?;
    }
    Ok(change)
}

pub(crate) async fn run_virsh(args: Vec<String>) -> Result<String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    host::run(VIRSH, &args).await
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidVmAutostartArgs {
    /// Exact VM name (the libvirt domain name).
    #[arg(long)]
    pub vm: String,
    /// Desired autostart state.
    #[arg(long)]
    pub enabled: bool,
    /// Apply the change. Without it the call only reports what it would do.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VmAutostartOutput {
    pub vm: String,
    pub enabled: bool,
    /// False when autostart was already in the requested state.
    pub changed: bool,
    /// True only when the change was applied: false for a dry run (where
    /// `changed` is what would happen) and for a no-op.
    pub executed: bool,
}

/// Set a VM's autostart flag on this machine (local virsh). Dry-run unless
/// `execute: true`; admin is required for both.
#[orca_tool(
    domain = "unraid",
    verb = "vm.autostart",
    role = "admin",
    data_mutation = true,
    execute_gated = false,
    reaches = ["privileged.apply"]
)]
async fn unraid_vm_autostart(
    args: UnraidVmAutostartArgs,
    ctx: &ToolCtx,
) -> Result<VmAutostartOutput> {
    require_admin("unraid.vm.autostart", ctx.caller().as_ref())?;
    crate::vm_availability::require().await?;
    let change = plan(&run_virsh, &args.vm, args.enabled).await?;
    if args.execute && change != Change::NoOp {
        let runner =
            privileged::runner().ok_or_else(|| anyhow!(privileged::missing_runner_blocker()))?;
        runner
            .run(&PrivilegedOp::SetVmAutostart {
                name: args.vm.clone(),
                on: args.enabled,
            })
            .await?;
    }
    Ok(VmAutostartOutput {
        vm: args.vm,
        enabled: args.enabled,
        changed: change != Change::NoOp,
        executed: args.execute && change != Change::NoOp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeVirsh {
        autostart: Mutex<Option<bool>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeVirsh {
        fn new(state: Option<bool>) -> Self {
            Self {
                autostart: Mutex::new(state),
                calls: Mutex::new(Vec::new()),
            }
        }

        async fn run(&self, args: Vec<String>) -> Result<String> {
            self.calls.lock().unwrap().push(args.clone());
            let mut st = self.autostart.lock().unwrap();
            let Some(on) = *st else {
                bail!("error: failed to get domain");
            };
            match args[0].as_str() {
                "-r" => Ok(format!(
                    "Id: -\nName: {}\nAutostart:      {}\n",
                    args[3],
                    if on { "enable" } else { "disable" }
                )),
                "autostart" => {
                    *st = Some(!args.iter().any(|a| a == "--disable"));
                    Ok(String::new())
                }
                _ => bail!("unexpected virsh call {args:?}"),
            }
        }
    }

    fn block<T>(f: impl Future<Output = T>) -> T {
        plugin_toolkit::reactor::block_on(f)
    }

    #[test]
    fn rejects_traversal_separators_controls_and_overlong() {
        let long = "a".repeat(MAX_VM_NAME + 1);
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "../x",
            "a\0b",
            "a\nb",
            "a\x1bb",
            &long,
            "7",
            "0042",
            "6f1c2b3a-0000-4e5f-8a9b-0123456789ab",
            "6F1C2B3A00004E5F8A9B0123456789AB",
        ] {
            assert!(validate_vm_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_vm_name("Home Assistant").is_ok());
        assert!(validate_vm_name("win11").is_ok());
        assert!(validate_vm_name(&"a".repeat(MAX_VM_NAME)).is_ok());
    }

    #[test]
    fn parses_dominfo_autostart() {
        assert!(parse_autostart("Name: x\nAutostart:      enable\n").unwrap());
        assert!(!parse_autostart("Autostart: disable").unwrap());
        assert!(parse_autostart("Name: x\n").is_err());
        assert!(parse_autostart("Autostart: maybe").is_err());
    }

    #[test]
    fn sets_through_virsh_idempotently() {
        let v = FakeVirsh::new(Some(false));
        let virsh = |a| v.run(a);
        let vm = "Home Assistant";
        assert_eq!(block(plan(&virsh, vm, false)).unwrap(), Change::NoOp);
        assert_eq!(block(set(&virsh, vm, true)).unwrap(), Change::Enable);
        assert_eq!(*v.autostart.lock().unwrap(), Some(true));
        assert_eq!(block(set(&virsh, vm, true)).unwrap(), Change::NoOp);
        assert_eq!(block(set(&virsh, vm, false)).unwrap(), Change::Disable);
        assert_eq!(*v.autostart.lock().unwrap(), Some(false));
        let calls = v.calls.lock().unwrap();
        assert!(calls.contains(&vec!["autostart".to_string(), "--domain".into(), vm.into()]));
        assert!(calls.contains(&vec![
            "autostart".to_string(),
            "--domain".into(),
            vm.into(),
            "--disable".into()
        ]));
    }

    #[test]
    fn unknown_vm_is_refused_without_a_change() {
        let v = FakeVirsh::new(None);
        let virsh = |a| v.run(a);
        assert!(block(set(&virsh, "pbs", true)).is_err());
        assert!(v.calls.lock().unwrap().iter().all(|c| c[0] != "autostart"));
    }

    #[test]
    fn invalid_name_never_reaches_virsh() {
        let v = FakeVirsh::new(Some(false));
        let virsh = |a| v.run(a);
        assert!(block(set(&virsh, "a\nb", true)).is_err());
        assert!(v.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn privileged_op_wire_form_is_tagged_snake_case() {
        let op = PrivilegedOp::SetVmAutostart {
            name: "pbs".into(),
            on: true,
        };
        let v = plugin_toolkit::serde_json::to_value(&op).unwrap();
        assert_eq!(v["op"], "set_vm_autostart");
        assert_eq!(v["payload"]["name"], "pbs");
        assert_eq!(v["payload"]["on"], true);
    }

    #[test]
    fn only_root_may_set_autostart() {
        let op = PrivilegedOp::SetVmAutostart {
            name: "pbs".into(),
            on: true,
        };
        let passwd = "orca:x:1000:100::/h:/bin/sh\n";
        let group = "docker:x:281:orca\n";
        assert!(privileged::authorize(&op, 0, passwd, group).is_ok());
        assert!(privileged::authorize(&op, 1000, passwd, group).is_err());
    }

    #[test]
    fn dry_run_requires_admin() {
        for role in [Some("user"), None] {
            let args = UnraidVmAutostartArgs {
                vm: "pbs".into(),
                enabled: true,
                execute: false,
            };
            let ctx = crate::authz::test_ctx(role);
            let e = block(unraid_vm_autostart(args, &ctx)).unwrap_err();
            assert!(e.to_string().contains("unraid.vm.autostart: "), "{e}");
        }
    }
}
