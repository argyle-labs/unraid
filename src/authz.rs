//! Caller authorization for verbs that run their own dry run.
//!
//! A verb that needs admin to execute also needs admin to dry-run: the plan
//! itself discloses host state and probes privileged paths. Such verbs set
//! `execute_gated = false`, so the central gate does not check for them, and
//! call [`require_admin`] before any planning.

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::prelude::*;

/// Fail closed: only an identified caller with role `admin` passes.
pub fn require_admin(tool: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    match caller {
        Some(c) if c.role == "admin" => Ok(()),
        Some(c) => bail!(
            "{tool}: requires role 'admin' (dry run included); caller '{}' has '{}'",
            c.username,
            c.role
        ),
        None => bail!(
            "{tool}: refused: the call carries no caller identity, so admin cannot be verified"
        ),
    }
}

/// A `ToolCtx` carrying a caller with `role`, or none, for verb tests.
#[cfg(test)]
pub(crate) fn test_ctx(role: Option<&str>) -> ToolCtx {
    use plugin_toolkit::contract::config::{Config, Model};
    use std::sync::Arc;
    let mut ctx = ToolCtx::new(Arc::new(Config {
        anthropic_api_key: None,
        lmstudio_url: String::new(),
        ollama_url: String::new(),
        default_model: Model::LMStudio {
            id: String::new(),
            url: String::new(),
        },
        app_dir: std::path::PathBuf::from("/tmp"),
        memory_root: std::path::PathBuf::from("/tmp"),
        db_path: std::path::PathBuf::from("/tmp/orca-unraid-authz-test.db"),
        ports: Default::default(),
    }));
    ctx.set_caller(role.map(|r| CallerIdentity {
        user_id: "1".into(),
        username: "u".into(),
        role: r.into(),
        can_mutate: true,
    }));
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(role: &str) -> CallerIdentity {
        CallerIdentity {
            user_id: "1".into(),
            username: "u".into(),
            role: role.into(),
            can_mutate: true,
        }
    }

    #[test]
    fn only_an_identified_admin_passes() {
        assert!(require_admin("t", Some(&caller("admin"))).is_ok());
        let e = require_admin("t", Some(&caller("user")))
            .unwrap_err()
            .to_string();
        assert!(e.contains("dry run included") && e.contains("'user'"));
        assert!(
            require_admin("t", None)
                .unwrap_err()
                .to_string()
                .contains("no caller identity")
        );
    }
}
