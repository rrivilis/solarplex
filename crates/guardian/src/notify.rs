//! The live seccomp-notify supervisor: Guardian's process-supervision loop
//! for a single sandboxed exec, built on raw `io_uring` rather than tokio.
//!
//! Guardian still processes one exec at a time (unchanged invariant --
//! `main.rs`'s outer request loop and the shim's `run_via_guardian` both
//! already assume this; true concurrent execs would need reworking both
//! sides' IPC correlation, out of scope here). What this module adds is
//! *within* that one exec: multiple event sources (the child's pidfd, its
//! seccomp notify fd, its stdout/stderr pipes, a deadline timer) that all
//! need watching for the exec's whole lifetime, not just once. `slab`-
//! indexed operation tracking maps each io_uring CQE's `user_data` back to
//! which of those sources completed -- this addresses multiple *outstanding
//! operations for the one active process*, not multiple concurrent
//! processes.
//!
//! Runs on a dedicated OS thread (`tokio::task::spawn_blocking` from
//! `executor.rs`), since `io_uring`'s `submit_and_wait` is a blocking call
//! that has no business running inside an async task -- tokio stays exactly
//! where it already is in `main.rs`'s outer request loop, this is a
//! separate, self-contained reactor, not a tokio integration.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use protocol::effects::DeclaredEffects;

use crate::seccomp_ffi;

pub struct SupervisedProcess {
    pub pidfd:     OwnedFd,
    pub notify_fd: OwnedFd,
    pub stdout_fd: OwnedFd,
    pub stderr_fd: OwnedFd,
    pub child_pid: i32,
    pub declared:  Arc<DeclaredEffects>,
    pub state:     ProcessState,
    pub stdout_buf: Vec<u8>,
    pub stderr_buf: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Starting,
    Running,
    /// Deadline hit, or the exec is being aborted for another reason: the
    /// process is being reaped/killed. No outstanding-notification flush
    /// is needed to get here -- `handle_notification` always RECVs and
    /// responds within one call, so there is never a notification left
    /// unanswered between poll iterations for this transition to clean up.
    Draining,
    Exited(RawExitStatus),
    Reaped,
}

/// `std::process::ExitStatus` isn't `Copy`/comparable the way this enum
/// wants; this is the raw `waitid` status word, decoded on demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawExitStatus(pub i32);

#[derive(Debug, Clone, Copy)]
enum OutstandingOp {
    PollPidfd,
    PollNotify,
    PollStdout,
    PollStderr,
    Deadline,
}

/// Outcome of one `run_supervised` call -- what `executor.rs` turns into
/// `GuardianResponse`.
pub struct SupervisionResult {
    pub stdout:    Vec<u8>,
    pub stderr:    Vec<u8>,
    pub exit_code: i32,
}

const DEADLINE: Duration = Duration::from_secs(300);

/// Runs the event loop to completion for one supervised process. Blocking;
/// call from a dedicated thread (`spawn_blocking`), never from an async task.
pub fn run_supervised(mut proc: SupervisedProcess) -> anyhow::Result<SupervisionResult> {
    use io_uring::{opcode, types, IoUring};

    let mut ring = IoUring::new(16)?;
    let mut ops: slab::Slab<OutstandingOp> = slab::Slab::with_capacity(8);

    // Pipes from std::process::Command's Stdio::piped() are blocking by
    // default. drain_pipe() below loops on read() until it sees "no more
    // data right now" -- on a blocking fd, "no more data right now" and
    // "no more data ever until the writer produces some" look identical to
    // read(), so it just blocks waiting for the next byte instead of
    // returning. That's a real deadlock, not a hypothetical one: if the
    // sandboxed process is itself paused on an unrelated seccomp
    // notification while this same event-loop thread is blocked inside
    // drain_pipe waiting for that same process to write more output,
    // neither side can make progress. O_NONBLOCK makes a drained pipe
    // return EAGAIN instead of blocking, which drain_pipe treats as "done
    // for now" rather than "done forever" (see there).
    for fd in [proc.stdout_fd.as_raw_fd(), proc.stderr_fd.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        }
    }

    let pidfd_key   = ops.insert(OutstandingOp::PollPidfd);
    let notify_key  = ops.insert(OutstandingOp::PollNotify);
    let stdout_key  = ops.insert(OutstandingOp::PollStdout);
    let stderr_key  = ops.insert(OutstandingOp::PollStderr);
    let deadline_key = ops.insert(OutstandingOp::Deadline);

    // Multishot poll: these fds are watched for the whole exec's lifetime,
    // not once. A one-shot POLL_ADD that's never resubmitted is exactly the
    // bug the standalone C seccomp-notify test harness found the hard way
    // (04-child-after-exec): the broker served one notification then
    // stopped listening, and the kernel's documented "no listener left"
    // behavior (ENOSYS on the next trapped syscall) looked like a mechanism
    // failure until root-caused. Multishot avoids needing the resubmit
    // dance at all for a fd watched this long.
    submit_multishot_poll(&mut ring, proc.pidfd.as_raw_fd(), pidfd_key as u64)?;
    submit_multishot_poll(&mut ring, proc.notify_fd.as_raw_fd(), notify_key as u64)?;
    submit_multishot_poll(&mut ring, proc.stdout_fd.as_raw_fd(), stdout_key as u64)?;
    submit_multishot_poll(&mut ring, proc.stderr_fd.as_raw_fd(), stderr_key as u64)?;

    let deadline_ts = types::Timespec::new().sec(DEADLINE.as_secs());
    let timeout_e = opcode::Timeout::new(&deadline_ts).build().user_data(deadline_key as u64);
    unsafe { ring.submission().push(&timeout_e)?; }
    ring.submit()?;

    proc.state = ProcessState::Running;
    tracing::info!(child_pid = proc.child_pid, "notify: supervising sandboxed exec");

    loop {
        match proc.state {
            ProcessState::Exited(_) | ProcessState::Reaped => break,
            _ => {}
        }

        ring.submit_and_wait(1)?;
        // Collect user_data of completed CQEs first -- the completion
        // queue borrows `ring`, and dispatch below needs `&mut ring` to
        // submit follow-up ops (ADDFD's underlying resolution doesn't
        // touch the ring, but CONTINUE/deny and re-arming a consumed
        // one-shot op would), so don't hold the completion-queue borrow
        // across dispatch.
        let completed: Vec<(u64, i32, u32)> = ring.completion()
            .map(|cqe| (cqe.user_data(), cqe.result(), cqe.flags()))
            .collect();

        for (user_data, result, flags) in completed {
            let Some(op) = ops.get(user_data as usize) else { continue };
            match *op {
                OutstandingOp::PollPidfd => {
                    if result > 0 {
                        // POLLIN on a pidfd means the process has exited.
                        // Nothing to flush here: `handle_notification`
                        // always RECVs and responds within the same call,
                        // so there is never an outstanding notification
                        // sitting unanswered between poll iterations for
                        // this state transition to need to clean up.
                        proc.state = ProcessState::Draining;
                        let status = reap(&proc)?;
                        tracing::info!(child_pid = proc.child_pid, exit_status = status.0, "notify: sandboxed exec exited");
                        proc.state = ProcessState::Exited(status);
                    }
                }
                OutstandingOp::PollNotify => {
                    if result > 0 {
                        handle_notification(&proc)?;
                    }
                }
                OutstandingOp::PollStdout => {
                    if result > 0 { drain_pipe(proc.stdout_fd.as_raw_fd(), &mut proc.stdout_buf); }
                }
                OutstandingOp::PollStderr => {
                    if result > 0 { drain_pipe(proc.stderr_fd.as_raw_fd(), &mut proc.stderr_buf); }
                }
                OutstandingOp::Deadline => {
                    // Same reasoning as the pidfd-exit branch above -- no
                    // outstanding notification can exist here to flush.
                    tracing::warn!(child_pid = proc.child_pid, deadline_secs = DEADLINE.as_secs(), "notify: deadline hit, killing sandboxed exec");
                    proc.state = ProcessState::Draining;
                    unsafe {
                        libc::syscall(libc::SYS_pidfd_send_signal, proc.pidfd.as_raw_fd(), libc::SIGKILL, std::ptr::null::<libc::c_void>(), 0);
                    }
                    let status = reap(&proc)?;
                    proc.state = ProcessState::Exited(status);
                }
            }
            // Multishot poll ops are *expected* to keep firing on their own
            // without resubmission -- but "expected to" isn't "guaranteed
            // to". IORING_CQE_F_MORE absent on a multishot poll means the
            // kernel terminated that registration (this is real, observed
            // behavior during end-to-end testing, not a hypothetical: the
            // notify_fd poll stopped generating completions after
            // successfully handling exactly one ADDFD, silently hanging
            // the whole event loop on the next syscall the sandboxed
            // process made -- there was nothing left armed to ever wake it
            // up again). Treat that as "needs re-arming", not "must have
            // been intentional", for every multishot poll, not just the
            // one this was first caught on.
            let poll_fd = match *op {
                OutstandingOp::PollPidfd  => Some(proc.pidfd.as_raw_fd()),
                OutstandingOp::PollNotify => Some(proc.notify_fd.as_raw_fd()),
                OutstandingOp::PollStdout => Some(proc.stdout_fd.as_raw_fd()),
                OutstandingOp::PollStderr => Some(proc.stderr_fd.as_raw_fd()),
                OutstandingOp::Deadline   => None,
            };
            let more_coming = io_uring::cqueue::more(flags);
            match poll_fd {
                Some(fd) if !more_coming => {
                    tracing::debug!(?op, fd, "notify: multishot poll terminated, re-arming");
                    submit_multishot_poll(&mut ring, fd, user_data as u64)?;
                }
                None if !more_coming => {
                    // The one genuinely one-shot op (Timeout) completing
                    // removes itself so a later, unrelated user_data
                    // collision can't be misattributed.
                    ops.remove(user_data as usize);
                }
                _ => {}
            }
        }
    }

    // Drain any remaining buffered output after the process has exited --
    // pipes can still have unread data sitting in the kernel buffer even
    // after the writer closed.
    drain_pipe(proc.stdout_fd.as_raw_fd(), &mut proc.stdout_buf);
    drain_pipe(proc.stderr_fd.as_raw_fd(), &mut proc.stderr_buf);

    let exit_code = match proc.state {
        ProcessState::Exited(RawExitStatus(status)) => decode_exit_code(status),
        _ => -1,
    };
    proc.state = ProcessState::Reaped;

    Ok(SupervisionResult { stdout: proc.stdout_buf, stderr: proc.stderr_buf, exit_code })
}

fn submit_multishot_poll(ring: &mut io_uring::IoUring, fd: RawFd, user_data: u64) -> anyhow::Result<()> {
    use io_uring::{opcode, types};
    let entry = opcode::PollAdd::new(types::Fd(fd), libc::POLLIN as u32)
        .multi(true)
        .build()
        .user_data(user_data);
    unsafe { ring.submission().push(&entry)?; }
    Ok(())
}

/// The dispatch policy: identify the requested path, check it against the
/// approved `DeclaredEffects`, and either `ADDFD` (a granted effect --
/// TOCTOU-safe, the tracee's real syscall never runs) or `CONTINUE` (not
/// one of ours; Landlock, installed independently and unchanged, is the
/// actual boundary for anything not specifically granted here -- see
/// `seccomp_ffi`'s module doc for why that composition is safe).
fn handle_notification(proc: &SupervisedProcess) -> anyhow::Result<()> {
    let notify_fd = proc.notify_fd.as_raw_fd();
    let req = match seccomp_ffi::notif_recv(notify_fd) {
        Ok(r) => r,
        // ENOENT here means the notification was already consumed/expired
        // (e.g. the tracee was killed between poll readiness and this
        // RECV) -- not an error worth propagating, just nothing to do.
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    if seccomp_ffi::notif_id_valid(notify_fd, req.id).is_err() {
        // Stale by the time we got here (PID-reuse race window) -- nothing
        // to respond to; the kernel already discarded this notification.
        return Ok(());
    }

    match resolve_and_authorize(&proc.declared, req.pid, &req) {
        Some(real_path) => {
            // Re-check immediately before acting on what was read -- narrows
            // (does not fully eliminate) the window between the memory read
            // inside resolve_and_authorize and this decision.
            if seccomp_ffi::notif_id_valid(notify_fd, req.id).is_err() {
                return Ok(());
            }
            match std::fs::File::open(&real_path) {
                Ok(file) => {
                    let addfd_result = seccomp_ffi::notif_addfd(notify_fd, req.id, file.as_raw_fd());
                    match &addfd_result {
                        Ok(injected_fd) => tracing::debug!(
                            pid = req.pid, nr = req.syscall_nr(), path = %real_path.display(),
                            srcfd = file.as_raw_fd(), injected_fd = injected_fd,
                            "notify: ADDFD ok (declared effect matched)",
                        ),
                        Err(e) => tracing::debug!(
                            pid = req.pid, nr = req.syscall_nr(), path = %real_path.display(),
                            srcfd = file.as_raw_fd(), error = %e,
                            "notify: ADDFD ioctl failed",
                        ),
                    }
                    // `file` (and the fd it owns) can drop here -- ADDFD
                    // already duplicated it into the tracee via
                    // SECCOMP_ADDFD_FLAG_SEND.
                }
                Err(e) => {
                    tracing::debug!(nr = req.syscall_nr(), path = %real_path.display(), error = %e, "notify: DENY (resolved path open failed)");
                    let _ = seccomp_ffi::notif_deny(notify_fd, req.id, libc::EACCES);
                }
            }
        }
        None => {
            tracing::debug!(nr = req.syscall_nr(), pid = req.pid, "notify: CONTINUE (not a declared effect)");
            let _ = seccomp_ffi::notif_continue(notify_fd, req.id);
        }
    }
    Ok(())
}

/// Reads the requested pathname exactly once from the tracee's memory (via
/// `/proc/<pid>/mem` at the openat-family syscall's pathname argument), then
/// resolves and authorizes it against `declared.file_effects` entirely from
/// Guardian's own knowledge.
///
/// This single read is what the ADDFD design's TOCTOU safety actually rests
/// on, and it's worth being precise about why it's safe when a later,
/// *second* resolution of the same pointer would not be: the vulnerability
/// this design closes is the kernel re-resolving a pathname pointer at
/// actual-syscall time (via `CONTINUE`), independently and later than
/// whatever inspection happened first -- a window a second tracee thread
/// can race by rewriting the string in between. Reading the pointer once,
/// here, and using those exact captured bytes for every downstream decision
/// (the match check, the `/proc/<pid>/root/<path>` open) has no second
/// resolution for anything to race against; the string the open acts on is
/// the same string that was authorized.
///
/// The specific `FileOps` flag required is matched to the actual notified
/// syscall (`unlink`/`unlinkat` needs `delete`, `rename*` needs `rename`,
/// `openat*` accepts any granted op), mirroring exactly the per-flag
/// `AccessFs` mapping `sandbox_entry.rs::apply_landlock` already does --
/// an early draft of this function checked only "is *any* ops flag granted
/// on this path" regardless of which syscall triggered the notification,
/// which would have over-granted (e.g. ADDFD'ing an `unlink()` against a
/// path only declared for `write`) relative to what Landlock itself would
/// allow for the exact same request.
///
/// Returns `None` if the memory read fails (no `CAP_SYS_PTRACE` and no
/// applicable ancestor exception) or the path isn't a declared, op-matching
/// effect -- both fall through to `CONTINUE` in the caller, deliberately:
/// Landlock is the real boundary for anything not specifically granted
/// here. Guardian's real deployment shape is the direct parent of its
/// sandboxed children (unlike the cross-process, deliberately-decoupled C
/// test harness this design was validated against), so under yama's
/// default `ptrace_scope=1` ("restricted ptrace") this read should succeed
/// via the ancestor exception without needing `CAP_SYS_PTRACE` at all --
/// worth confirming during end-to-end verification rather than assumed,
/// since it wasn't the scenario the C harness actually exercised.
fn resolve_and_authorize(
    declared: &DeclaredEffects,
    pid: u32,
    req: &seccomp_ffi::SeccompNotif,
) -> Option<std::path::PathBuf> {
    let requested = read_tracee_cstring(pid, req.args[1])?;
    let nr = req.syscall_nr();
    let needs_op: fn(&protocol::effects::FileOps) -> bool =
        if nr == libc::SYS_unlink || nr == libc::SYS_unlinkat {
            |ops| ops.delete
        } else if nr == libc::SYS_rename || nr == libc::SYS_renameat || nr == libc::SYS_renameat2 {
            |ops| ops.rename
        } else {
            // openat/openat2: a plain read-open is never registered as a
            // FileEffect at all (see DeclaredEffects::from_scout), so any
            // declared effect on this path at all is sufficient here --
            // distinguishing read-open from write/create/trunc would need
            // parsing the syscall's flags argument, which this design
            // deliberately doesn't need to (the pathname is the only
            // argument whose TOCTOU safety this mechanism is about).
            |ops| ops.any()
        };

    for fe in &declared.file_effects {
        if !needs_op(&fe.ops) { continue; }
        if !fe.path.matches(&requested) { continue; }
        return Some(std::path::PathBuf::from(format!("/proc/{pid}/root{requested}")));
    }
    None
}

fn read_tracee_cstring(pid: u32, addr: u64) -> Option<String> {
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    // PATH_MAX is 4096 on Linux; read a generous chunk and stop at the
    // first NUL rather than assuming the exact length up front.
    let mut buf = vec![0u8; 4096];
    // pread (via read_at), not seek+read -- the correct primitive for a
    // random-access read at a known offset regardless of any other use of
    // this fd (there is none here today, but this is the right call
    // either way).
    let n = file.read_at(&mut buf, addr).ok()?;
    let nul = buf[..n].iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..nul].to_vec()).ok()
}

/// Assumes `fd` is already O_NONBLOCK (set once in run_supervised) -- on a
/// blocking fd this would hang the whole event-loop thread the moment the
/// pipe is temporarily empty, which is exactly what happened before that
/// flag was added: a real deadlock, this thread blocked here waiting for
/// more output from a process that was itself blocked waiting for this
/// same thread to answer an unrelated seccomp notification. `n < 0` here
/// covers both a real error and EAGAIN/EWOULDBLOCK (no data available
/// *right now*, not "never again") -- both correctly mean "stop for now,
/// the next multishot poll completion will call this again."
fn drain_pipe(fd: RawFd, buf: &mut Vec<u8>) {
    let mut chunk = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
        if n <= 0 { break; }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
}

fn reap(proc: &SupervisedProcess) -> anyhow::Result<RawExitStatus> {
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            proc.pidfd.as_raw_fd() as libc::id_t,
            &mut siginfo,
            libc::WEXITED,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // si_status carries the exit code (WEXITED) or the terminating signal,
    // depending on si_code -- decode_exit_code below interprets it the same
    // way `ExitStatus`'s own Display/code() would.
    let status = unsafe { siginfo.si_status() };
    Ok(RawExitStatus(status))
}

fn decode_exit_code(raw: i32) -> i32 {
    // waitid's si_status for CLD_EXITED is already the plain exit code (not
    // the raw wait(2) status word `waitpid` returns), so no WIFEXITED/
    // WEXITSTATUS unpacking is needed here -- unlike a raw `waitpid` status.
    raw
}
