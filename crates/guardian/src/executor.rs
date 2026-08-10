//! Ring-2 sandboxed executor — guardian's execution authority.
//!
//! This is the guardian's sole executable surface: it receives an approved
//! command + declared effects from the shim, constructs the sandbox, and runs
//! the command inside it.  The guardian binary is the only process on the host
//! that holds the Linux capabilities needed for bwrap namespace construction.
//!
//! See `crates/sidecar/src/executor.rs` for the design notes; this module is
//! structurally identical but references `solarplex-guardian` instead of
//! `solarplex-sidecar` as the sandbox-entry binary.

use anyhow::Result;
use protocol::effects::DeclaredEffects;

pub struct ExecResult {
    pub stdout:    String,
    pub stderr:    String,
    pub exit_code: i32,
}

pub async fn ring2_exec(command: &str, declared: &DeclaredEffects) -> Result<ExecResult> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    let declared = declared;
    #[cfg(target_os = "linux")]
    {
        if let Some(bwrap) = find_bwrap() {
            return exec_sandboxed(command, declared, &bwrap).await;
        }
        // Fail-closed by default: no sandbox → refuse to execute.
        // Set SOLARPLEX_ALLOW_UNSANDBOXED=1 to permit unsandboxed execution
        // (development and testing only — NOT safe for production).
        if std::env::var("SOLARPLEX_ALLOW_UNSANDBOXED").is_ok() {
            tracing::warn!(
                command,
                "bwrap unavailable — executing unsandboxed (SOLARPLEX_ALLOW_UNSANDBOXED is set; not for production)"
            );
            return exec_unsandboxed(command).await;
        }
        anyhow::bail!(
            "bwrap not found; refusing to execute unsandboxed. \
             Set SOLARPLEX_ALLOW_UNSANDBOXED=1 to override (development only)"
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Ring-2 sandbox requires Linux bwrap. Fail closed unless explicitly opted out.
        if std::env::var("SOLARPLEX_ALLOW_UNSANDBOXED").is_ok() {
            tracing::warn!(
                command,
                "non-Linux platform — Ring-2 sandbox unavailable; executing unsandboxed (SOLARPLEX_ALLOW_UNSANDBOXED)"
            );
            return exec_unsandboxed(command).await;
        }
        anyhow::bail!(
            "Ring-2 sandbox requires Linux; refusing to execute unsandboxed. \
             Set SOLARPLEX_ALLOW_UNSANDBOXED=1 to override (development only)"
        );
    }
}

#[cfg(target_os = "linux")]
async fn exec_sandboxed(command: &str, declared: &DeclaredEffects, bwrap: &str) -> Result<ExecResult> {
    // The guardian binary itself is both the outer executor (this function)
    // and the inner sandbox-entry process (via the `sandbox-entry` subcommand).
    let guardian_exe = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("solarplex-guardian"));

    let mut cmd = tokio::process::Command::new(bwrap);

    cmd.args(["--ro-bind", "/", "/"]);
    cmd.args(["--tmpfs", "/tmp"]);
    cmd.args(["--dev", "/dev"]);
    cmd.args(["--proc", "/proc"]);

    for fe in &declared.file_effects {
        let anchor = fe.path.anchor_path();
        if std::path::Path::new(anchor).exists() {
            cmd.args(["--bind", anchor, anchor]);
        } else {
            cmd.args(["--dir", anchor]);
        }
    }

    let tmp_declared = declared.file_effects.iter()
        .any(|fe| fe.path.matches("/tmp") || fe.path.anchor_path() == "/tmp");
    if tmp_declared {
        cmd.args(["--bind", "/tmp", "/tmp"]);
    }

    if !declared.network_access {
        cmd.arg("--unshare-net");
    }
    cmd.arg("--unshare-pid");
    cmd.arg("--unshare-ipc");

    // Inner command: solarplex-guardian sandbox-entry applies landlock + seccomp.
    cmd.arg("--");
    cmd.arg(guardian_exe.to_string_lossy().as_ref());
    cmd.arg("sandbox-entry");

    if !declared.network_access    { cmd.arg("--no-network"); }
    if !declared.subprocess_exec   { cmd.arg("--no-subprocess"); }
    if declared.allow_dynamic_paths { cmd.arg("--allow-dynamic"); }

    for fe in &declared.file_effects {
        if fe.ops.any() {
            cmd.arg("--file-effect");
            cmd.arg(format!("{}:{}", encode_file_ops(&fe.ops), fe.path.anchor_path()));
        }
    }

    // Guardian-deployment resource ceiling (file/env/flags — see
    // resource_policy.rs), not part of DeclaredEffects: this is host
    // capacity policy, not the operation's declared authority.
    for arg in crate::resource_policy::effective_limits().to_cli_args() {
        cmd.arg(arg);
    }

    cmd.arg("--");
    cmd.args(["sh", "-c", command]);

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let out = cmd.output().await
        .map_err(|e| anyhow::anyhow!("bwrap exec failed: {e}"))?;

    Ok(ExecResult {
        stdout:    String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr:    String::from_utf8_lossy(&out.stderr).into_owned(),
        exit_code: out.status.code().unwrap_or(-1),
    })
}

#[cfg(target_os = "linux")]
fn find_bwrap() -> Option<String> {
    for path in &["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    if std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some("bwrap".to_string());
    }
    None
}

#[cfg(target_os = "linux")]
fn encode_file_ops(ops: &protocol::effects::FileOps) -> String {
    let mut s = String::with_capacity(4);
    if ops.create { s.push('c'); }
    if ops.write  { s.push('w'); }
    if ops.delete { s.push('d'); }
    if ops.rename { s.push('r'); }
    s
}

async fn exec_unsandboxed(command: &str) -> Result<ExecResult> {
    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    let flag  = if cfg!(windows) { "/C" } else { "-c" };
    let out = tokio::process::Command::new(shell)
        .args([flag, command])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output().await
        .map_err(|e| anyhow::anyhow!("shell exec failed: {e}"))?;
    Ok(ExecResult {
        stdout:    String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr:    String::from_utf8_lossy(&out.stderr).into_owned(),
        exit_code: out.status.code().unwrap_or(-1),
    })
}
