//! Ring-2 sandboxed executor; guardian's execution authority.
//!
//! This is the guardian's sole executable surface: it receives an approved
//! command + declared effects from the shim, constructs the sandbox, and runs
//! the command inside it.  The guardian binary is the only process on the host
//! that holds the Linux capabilities needed for bwrap namespace construction.
//!
//! Spawns bwrap (with `solarplex-guardian sandbox-entry` as its inner
//! command -- see `sandbox_entry.rs`), then hands the spawned child's
//! pidfd, seccomp-notify fd, and stdio pipes to `notify.rs`'s io_uring-based
//! supervisor for the exec's whole lifetime, rather than just blocking on
//! the command's exit -- see that module's doc for why a live-mediated
//! sandbox needs an active broker loop, not a spawn-and-wait.

use anyhow::Result;
use protocol::effects::DeclaredEffects;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
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
                "bwrap unavailable, executing unsandboxed (SOLARPLEX_ALLOW_UNSANDBOXED is set; not for production)"
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
                "non-Linux platform, sandbox unavailable; executing unsandboxed (SOLARPLEX_ALLOW_UNSANDBOXED)"
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
async fn exec_sandboxed(
    command: &str,
    declared: &DeclaredEffects,
    bwrap: &str,
) -> Result<ExecResult> {
    // The guardian binary itself is both the outer executor (this function)
    // and the inner sandbox-entry process (via the `sandbox-entry` subcommand).
    let guardian_exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("solarplex-guardian"));

    // std::process::Command, not tokio::process -- live supervision (pidfd +
    // seccomp-notify + stdio, all through one io_uring instance) happens on
    // a dedicated thread in notify.rs, not through tokio's own process
    // reaping. Confirmed empirically (not assumed) that an inherited fd
    // this process doesn't explicitly close survives both bwrap's own exec
    // and the inner sandboxed command's exec, so the same socketpair fd
    // dup2'd here is what sandbox_entry.rs sees as NOTIFY_FD_RENDEZVOUS.
    let mut cmd = std::process::Command::new(bwrap);

    // Purpose-built OCI-derived image when configured (crate::rootfs) --
    // falls back to the real host filesystem, read-only, otherwise. See
    // rootfs.rs's module doc for why the fallback is a WARN-and-degrade,
    // not a fail-closed refusal the way landlock/seccomp setup failures are.
    match crate::rootfs::sandbox_rootfs() {
        Some(image_root) => {
            cmd.arg("--ro-bind").arg(image_root).arg("/");
        }
        None => {
            cmd.args(["--ro-bind", "/", "/"]);
        }
    }
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

    let tmp_declared = declared
        .file_effects
        .iter()
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

    if !declared.network_access {
        cmd.arg("--no-network");
    }
    if !declared.subprocess_exec {
        cmd.arg("--no-subprocess");
    }
    if declared.allow_dynamic_paths {
        cmd.arg("--allow-dynamic");
    }

    for fe in &declared.file_effects {
        if fe.ops.any() {
            let (dev, ino) = match fe.identity {
                Some((d, i)) => (d.to_string(), i.to_string()),
                None => ("-".to_string(), "-".to_string()),
            };
            cmd.arg("--file-effect");
            cmd.arg(format!(
                "{}:{dev}:{ino}:{}",
                encode_file_ops(&fe.ops),
                fe.path.anchor_path()
            ));
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

    // Socketpair for the fd-5 seccomp-notify rendezvous: sandbox_entry.rs
    // (running inside the bwrap sandbox, after its own execvp) sends the
    // notify fd it installs back over this once ready. Confirmed
    // empirically (not assumed) that bwrap forwards an inherited fd through
    // into the sandboxed inner command by default, no bwrap flag needed --
    // see this function's opening comment.
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(anyhow::anyhow!(
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let (parent_end, child_end) = (sv[0], sv[1]);

    // SAFETY: pre_exec runs in the forked child, after fork but before
    // exec, so only async-signal-safe operations are permitted here --
    // dup2 and close both qualify. The dup2'd fd is not CLOEXEC, so it
    // survives both bwrap's own exec and (per the confirmed fd-forwarding
    // behavior) the inner sandboxed command's exec too.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            if libc::dup2(child_end, crate::NOTIFY_FD_RENDEZVOUS) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(child_end);
            libc::close(parent_end);
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("bwrap spawn failed: {e}"))?;
    // Parent's own copy of the child's socket end is no longer needed --
    // the child has its own (dup2'd) copy now via pre_exec above.
    unsafe {
        libc::close(child_end);
    }

    // pidfd_open immediately after spawn -- the same "nothing else in this
    // process reaps children behind our back" pattern already validated
    // live end-to-end (the standalone C seccomp-notify test harness's
    // scenarios 1-8 all used this exact ordering successfully on a real
    // kernel). Guardian only ever spawns bwrap for a sandboxed exec; there
    // is no other child-reaping code path in this process to race against.
    let child_pid = child.id() as i32;
    let pidfd = unsafe {
        let fd = libc::syscall(libc::SYS_pidfd_open, child_pid, 0) as i32;
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "pidfd_open failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        std::os::fd::OwnedFd::from_raw_fd(fd)
    };

    let notify_fd = match crate::fd_passing::recv_fd(parent_end) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe {
                libc::close(parent_end);
            }
            // The sandboxed child failed before ever reaching the point of
            // sending the notify fd back -- whatever it (or bwrap) printed
            // about why is sitting unread in its stdout/stderr pipes.
            // Surface that instead of just the generic "no fd received",
            // since this is otherwise a dead end to debug.
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            if let Some(mut s) = child.stdout.take() {
                let _ = std::io::Read::read_to_end(&mut s, &mut stdout_buf);
            }
            if let Some(mut s) = child.stderr.take() {
                let _ = std::io::Read::read_to_end(&mut s, &mut stderr_buf);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow::anyhow!(
                "failed to receive seccomp-notify fd from sandboxed child: {e}\n\
                 -- bwrap/sandbox-entry stdout: {}\n\
                 -- bwrap/sandbox-entry stderr: {}",
                String::from_utf8_lossy(&stdout_buf),
                String::from_utf8_lossy(&stderr_buf),
            ));
        }
    };
    unsafe {
        libc::close(parent_end);
    }

    let stdout_owned: std::os::fd::OwnedFd = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("bwrap child has no stdout pipe"))?
        .into();
    let stderr_owned: std::os::fd::OwnedFd = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("bwrap child has no stderr pipe"))?
        .into();

    let supervised = crate::notify::SupervisedProcess {
        pidfd,
        notify_fd,
        stdout_fd: stdout_owned,
        stderr_fd: stderr_owned,
        child_pid,
        declared: std::sync::Arc::new(declared.clone()),
        state: crate::notify::ProcessState::Starting,
        stdout_buf: Vec::new(),
        stderr_buf: Vec::new(),
    };

    // The io_uring supervisor's submit_and_wait is a blocking call with no
    // business running inside an async task -- see notify.rs's module doc.
    // `child` (the std::process::Child handle) is dropped here without
    // calling its own .wait(): the supervisor performs the actual,
    // authoritative reap itself via waitid(P_PIDFD, ...) on the pidfd
    // (notify.rs::reap), which is what clears the zombie -- `child` here
    // has already served its only purpose (spawning, and handing over the
    // stdout/stderr pipes above).
    let result = tokio::task::spawn_blocking(move || crate::notify::run_supervised(supervised))
        .await
        .map_err(|e| anyhow::anyhow!("supervisor thread panicked: {e}"))??;

    Ok(ExecResult {
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        exit_code: result.exit_code,
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
    if ops.create {
        s.push('c');
    }
    if ops.write {
        s.push('w');
    }
    if ops.delete {
        s.push('d');
    }
    if ops.rename {
        s.push('r');
    }
    s
}

async fn exec_unsandboxed(command: &str) -> Result<ExecResult> {
    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    let flag = if cfg!(windows) { "/C" } else { "-c" };
    let out = tokio::process::Command::new(shell)
        .args([flag, command])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("shell exec failed: {e}"))?;
    Ok(ExecResult {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        exit_code: out.status.code().unwrap_or(-1),
    })
}
