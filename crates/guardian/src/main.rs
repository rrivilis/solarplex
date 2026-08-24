mod executor;
// SCM_RIGHTS fd passing for the fd-5 seccomp-notify rendezvous -- used by
// both executor.rs (parent side) and sandbox_entry.rs (child side), both
// Linux-only call sites, but the helpers themselves are plain libc/sockets
// with nothing target_os-gated inside them.
#[cfg(target_os = "linux")]
mod fd_passing;
// The io_uring-based process supervisor -- see its own module doc.
#[cfg(target_os = "linux")]
mod notify;
mod resource_policy;
// Entirely Linux-specific (loopback mounts, /proc/mounts, the oci2rootfs
// dependency itself is only pulled in for target_os = "linux" — see
// Cargo.toml). Only `executor.rs`'s Linux-gated `exec_sandboxed` calls in.
#[cfg(target_os = "linux")]
mod rootfs;
mod sandbox_entry;
// Raw seccomp-notify FFI (struct layouts, ioctl codes, BPF construction) --
// see its own module doc for why this is hand-rolled rather than built on
// a crate.
#[cfg(target_os = "linux")]
mod seccomp_ffi;
mod verify;

use anyhow::Result;
use protocol::ipc;

// The shim dup2's one end of a socketpair to this fd before exec-ing the guardian.
// Possession of the fd IS the authority — no ChannelHello or SO_PEERCRED needed.
// Matches GUARDIAN_IPC_FD in shim/src/main.rs.
const GUARDIAN_IPC_FD: i32 = 4;

// executor.rs dup2's one end of a socketpair to this fd in the sandboxed
// child before exec-ing bwrap. sandbox_entry.rs (running as that child,
// post-bwrap) sends the seccomp-notify fd back over it via SCM_RIGHTS once
// installed — the same inherited-fd-is-authority pattern as
// GUARDIAN_IPC_FD/fd 3 (shim<->adapter) above, applied one level further
// in. pub(crate): read by both executor.rs (the parent side) and
// sandbox_entry.rs (the child side).
#[cfg(target_os = "linux")]
pub(crate) const NOTIFY_FD_RENDEZVOUS: i32 = 5;

/// Guardian entry point.
///
/// Two modes:
/// - `sandbox-entry [opts] -- CMD`: apply landlock + seccomp, exec CMD.
///   Invoked by bwrap as the inner process inside the namespace.
/// - (default): open the pre-established IPC socket at fd GUARDIAN_IPC_FD,
///   process GuardianRequests from the shim, independently verify + fetch each
///   approved command from the server, then execute under sandbox.
// Deliberately not `#[tokio::main]`: that macro builds a multi-threaded
// runtime (extra OS threads) before any of this function's own body runs,
// including the sandbox-entry check below. sandbox_entry::run() installs a
// SECCOMP_FILTER_FLAG_NEW_LISTENER filter without TSYNC (thread-scoped by
// design) and then execvp's -- it never awaits anything, so it has no need
// for tokio at all, and running it with an extra live worker thread already
// present at seccomp-install/execve time is exactly the kind of surprising
// state a security-sensitive exec path shouldn't carry, whether or not it
// is presently the cause of any specific bug. The tokio runtime is built
// manually below, only for the non-sandbox-entry (outer request loop) path.
fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.get(1).map(|s| s.as_str()) == Some("sandbox-entry") {
        sandbox_entry::run(&raw_args[2..]);
        // run() diverges (exec or exit); this line is unreachable.
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "solarplex_guardian=info".into()),
        )
        .init();

    let api_base = std::env::var("SOLARPLEX_WS")
        .unwrap_or_else(|_| "http://localhost:8080".into())
        .replace("ws://", "http://")
        .replace("wss://", "https://");
    let session_id = std::env::var("SOLARPLEX_SESSION_ID")
        .map_err(|_| anyhow::anyhow!("SOLARPLEX_SESSION_ID is required"))?;
    let actor_id = std::env::var("SOLARPLEX_ACTOR_ID")
        .map_err(|_| anyhow::anyhow!("SOLARPLEX_ACTOR_ID is required"))?;
    let fail_open = std::env::var("SOLARPLEX_GUARDIAN_FAIL_OPEN")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    if fail_open {
        tracing::warn!("guardian: SOLARPLEX_GUARDIAN_FAIL_OPEN=1 — fail-closed disabled (dev only)");
    }

    // IMA appraisal and dm-verity are NOT enforced at runtime.
    // Binary integrity verification requires deployment-level kernel configuration
    // (CONFIG_IMA, signed dm-verity root hash, IMA policy with EXECUTE appraisal rules).
    // Until those are in place, a compromised guardian binary can bypass all guards.
    // See THREAT_MODEL.md §11.1 for the full gap description.
    tracing::warn!(
        "guardian: IMA appraisal and dm-verity are NOT enforced — \
         binary integrity requires deployment-level kernel configuration (THREAT_MODEL.md §11.1)"
    );

    // Neither layer is active in *any* current deployment (dev, CI, or
    // production) per THREAT_MODEL.md §4.6, so the warning above is
    // deliberately unconditional and non-fatal by default — defaulting to
    // fail-closed here would break every existing deployment, unlike
    // find_bwrap()'s fail-closed default in executor.rs, where the
    // sandboxing tool genuinely is expected to be present today.
    //
    // SOLARPLEX_REQUIRE_IMA is the inverse: an explicit *opt-in* assertion
    // for an operator who has actually deployed the kernel-level pieces and
    // wants a misconfiguration (policy failed to load, wrong image mounted)
    // to be a loud startup failure instead of a log line nobody reads. Same
    // parsing convention as SOLARPLEX_GUARDIAN_FAIL_OPEN above.
    let require_ima = std::env::var("SOLARPLEX_REQUIRE_IMA")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if require_ima {
        if ima_appraisal_appears_active() {
            tracing::info!(
                "guardian: SOLARPLEX_REQUIRE_IMA=1 — IMA policy interface detected, continuing"
            );
        } else {
            tracing::error!(
                "guardian: SOLARPLEX_REQUIRE_IMA=1 but /sys/kernel/security/ima/policy is \
                 absent — IMA appraisal does not appear active on this host. Refusing to \
                 start rather than run with an asserted protection silently missing. Unset \
                 SOLARPLEX_REQUIRE_IMA to start without this assertion (not for production)."
            );
            anyhow::bail!("SOLARPLEX_REQUIRE_IMA=1 but IMA appraisal is not active");
        }
    }

    #[cfg(unix)]
    return run_unix(api_base, session_id, actor_id, fail_open).await;

    // Pre-existing gap, not introduced here: this crate previously had no
    // non-Unix arm at all, so a Windows toolchain couldn't even type-check
    // it (unlike crates/shim, which already has this exact fallback). Added
    // in passing while verifying SOLARPLEX_REQUIRE_IMA compiles cleanly —
    // matches shim/src/main.rs's identical pattern.
    #[cfg(not(unix))]
    {
        let _ = (api_base, session_id, actor_id, fail_open);
        anyhow::bail!("solarplex-guardian requires a Unix operating system");
    }
}

/// Best-effort userspace signal for whether IMA appraisal is active on this
/// host — not itself a security control, and not trustworthy against the
/// exact threat it's guarding: a sufficiently privileged attacker who has
/// already replaced this binary could patch out or fool this check too. The
/// only *trustworthy* enforcement point is the kernel itself, at `execve`
/// time, before any of this code ever runs (THREAT_MODEL.md §4.6). This
/// exists purely to turn "IMA was documented as required but the deployment
/// forgot to enable it" from a silent gap into a loud one, mirroring
/// `find_bwrap()`'s existing fail-closed-unless-opted-out shape for the
/// Ring-2 sandbox.
///
/// `/sys/kernel/security/ima/policy` exists only when IMA is compiled into
/// the kernel, securityfs is mounted, and *some* policy has been loaded.
/// Its absence reliably proves IMA is not enforcing anything at all — the
/// case this check exists to catch. Its presence does not by itself prove a
/// rule actually appraises this specific binary; that still needs a human
/// policy audit, which is why this is a startup assertion gate, not a
/// substitute for one.
fn ima_appraisal_appears_active() -> bool {
    std::path::Path::new("/sys/kernel/security/ima/policy").exists()
}

#[cfg(unix)]
async fn run_unix(
    api_base:   String,
    session_id: String,
    actor_id:   String,
    fail_open:  bool,
) -> Result<()> {
    use std::os::unix::io::FromRawFd;

    // Set CLOEXEC on the inherited fd immediately so bwrap sandbox children
    // cannot inherit the guardian↔shim authority socket.
    unsafe {
        let flags = libc::fcntl(GUARDIAN_IPC_FD, libc::F_GETFD);
        libc::fcntl(GUARDIAN_IPC_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }

    // Claim ownership of the inherited fd and wrap it as a tokio stream.
    // The shim dup2'd one end of a socketpair to GUARDIAN_IPC_FD before exec.
    // Fd possession is the authority; SO_PEERCRED and ChannelHello are not needed.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(GUARDIAN_IPC_FD) };
    std_stream.set_nonblocking(true)?;
    let mut stream = tokio::net::UnixStream::from_std(std_stream)?;

    tracing::info!("guardian: ready on inherited fd {GUARDIAN_IPC_FD}");

    // Guardian processes requests strictly sequentially — bwrap runs each
    // command synchronously, so there is never more than one in-flight request.
    loop {
        let req: ipc::GuardianRequest = match ipc::read_frame(&mut stream).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                tracing::warn!("guardian: read error: {e}");
                break;
            }
        };

        tracing::info!(
            approval_id = %req.approval_id,
            "guardian: received exec request",
        );

        let resp = handle_request(req, &api_base, &session_id, &actor_id, fail_open).await;

        if let Err(e) = ipc::write_frame(&mut stream, &resp).await {
            tracing::warn!("guardian: write error: {e}");
            break;
        }
    }

    tracing::info!("guardian: IPC connection closed — exiting");
    Ok(())
}

async fn handle_request(
    req:        ipc::GuardianRequest,
    api_base:   &str,
    session_id: &str,
    actor_id:   &str,
    fail_open:  bool,
) -> ipc::GuardianResponse {
    // Independent verification: fetch approval status AND server-canonical
    // command + declared effects in a single call.  The adapter never supplies
    // the command; only the server's record drives what we execute.
    let approved = match verify::verify_and_fetch(&req.approval_id, api_base, session_id, actor_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::error!(
                approval_id = %req.approval_id,
                "guardian: server denied approval — refusing to execute",
            );
            return error_response(req, "approval not granted by server");
        }
        Err(e) => {
            if fail_open {
                // SOLARPLEX_GUARDIAN_FAIL_OPEN=1: log as WARN instead of ERROR.
                // NOTE: with the current design the guardian cannot proceed
                // anyway (no command to run), so this flag only affects log
                // severity, not behavior.
                tracing::warn!(
                    approval_id = %req.approval_id,
                    "guardian: server unreachable ({e}) — fail-closed (FAIL_OPEN has no exec effect)",
                );
            } else {
                tracing::error!(
                    approval_id = %req.approval_id,
                    "guardian: server unreachable ({e}) — refusing to execute (fail-closed)",
                );
            }
            return error_response(req, &format!("server unreachable: {e}"));
        }
    };

    tracing::info!(
        approval_id = %req.approval_id,
        command     = %approved.command,
        "guardian: executing approved command",
    );

    match executor::ring2_exec(&approved.command, &approved.declared).await {
        Ok(result) => ipc::GuardianResponse {
            id:          req.id,
            approval_id: req.approval_id,
            stdout:      result.stdout,
            stderr:      result.stderr,
            exit_code:   result.exit_code,
            error:       None,
        },
        Err(e) => error_response(req, &format!("sandbox exec failed: {e}")),
    }
}

fn error_response(req: ipc::GuardianRequest, msg: &str) -> ipc::GuardianResponse {
    ipc::GuardianResponse {
        id:          req.id,
        approval_id: req.approval_id,
        stdout:      String::new(),
        stderr:      String::new(),
        exit_code:   -1,
        error:       Some(msg.to_string()),
    }
}

