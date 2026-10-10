//! Runahead scout for the shim — identical to the sidecar's scout.rs
//! but referencing the shim's own SessionClient.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, Mutex};

use protocol::effects::{ExecutionManifest, FileEvent, FileOps, ScoutManifest};

// The strace-output parsing below (through `is_failed_syscall`) is plain
// string parsing with no Linux-specific API calls -- only `run_scout_linux`,
// which actually spawns `strace`, needs the platform gate. Keeping the
// parsers themselves portable means they compile and are unit-testable on
// every dev platform, not just Linux.

const MAX_EVENTS: usize = 1_000;

const NOISE_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/share/",
    "/lib/",
    "/lib64/",
    "/etc/ld.so",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
];

pub fn extract_command(args: &serde_json::Value) -> Option<String> {
    for field in &["command", "cmd", "shell", "script", "run"] {
        if let Some(s) = args.get(field).and_then(|v| v.as_str()) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub async fn run_scout(command: &str, timeout_secs: u64) -> ScoutManifest {
    #[cfg(target_os = "linux")]
    {
        run_scout_linux(command, timeout_secs).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = timeout_secs;
        ScoutManifest {
            command: command.to_string(),
            sandbox_backend: "none".to_string(),
            ..Default::default()
        }
    }
}

pub fn build_execution_manifest(
    pre: &HashMap<String, (i64, u64)>,
    post: &HashMap<String, (i64, u64)>,
    scout: Option<&ScoutManifest>,
) -> ExecutionManifest {
    let scout_writes: Vec<String> = scout
        .map(|m| m.file_effects.iter().map(|fe| fe.path.clone()).collect())
        .unwrap_or_default();

    let mut files_changed = Vec::new();
    let mut unexpected_writes = Vec::new();

    for (path, &post_meta) in post {
        let changed = match pre.get(path) {
            Some(&pre_meta) => pre_meta != post_meta,
            None => true,
        };
        if changed {
            files_changed.push(path.clone());
            if !scout_writes.contains(path) {
                unexpected_writes.push(path.clone());
            }
        }
    }

    let missing_writes: Vec<String> = scout_writes
        .iter()
        .filter(|expected| {
            let changed = match (pre.get(*expected), post.get(*expected)) {
                (Some(&p), Some(&q)) => p != q,
                (None, Some(_)) => true,
                _ => false,
            };
            !changed
        })
        .cloned()
        .collect();

    ExecutionManifest {
        files_changed,
        missing_writes,
        unexpected_writes,
    }
}

// ── Linux strace backend ──────────────────────────────────────────────────────
//
// The scout learns what a command *would* do by running it once under
// `strace` while the human is still deciding. That means the command runs
// BEFORE anyone has approved it, so it must not be able to have any real
// effect. It therefore runs inside a throwaway bubblewrap sandbox:
//
//   - the whole filesystem is bound read-only, so a write to a real path
//     fails with `EROFS` instead of landing;
//   - `/tmp` is a small private tmpfs, discarded with the sandbox;
//   - there is no network namespace to speak of (`--unshare-net`), so a
//     `connect` goes nowhere;
//   - the environment is cleared down to an allowlist, so the shim's own
//     secrets (tokens, cloud credentials) are not visible to the command;
//   - `--die-with-parent` + a private pid namespace mean that when the scout
//     times out and strace is killed, everything it started goes with it.
//
// Observing a write that was *refused* is still observing the intent, which
// is what the sandbox policy is built from: the parsers below record a
// sandbox-denied write or connect, not just a successful one. The cost is
// fidelity, not safety: a command that aborts at its first refused write
// yields a partial manifest, and the real run's sandbox (built from that
// manifest) then fails closed on whatever the scout never saw.
//
// If the sandbox is unavailable the scout does NOT run the command. An
// explicit `SOLARPLEX_ALLOW_UNSANDBOXED` opt-out (the same one the guardian
// honors, development only) restores the old unsandboxed behavior.

#[cfg(target_os = "linux")]
const SCOUT_BACKEND_SANDBOXED: &str = "strace+bwrap(ro,no-net)";
#[cfg(target_os = "linux")]
const SCOUT_BACKEND_UNSANDBOXED: &str = "strace(unsandboxed)";

/// Per-file size cap for anything the scouted command (or strace's own log)
/// writes, and the size of the private `/tmp`.
#[cfg(target_os = "linux")]
const SCOUT_SCRATCH_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn find_bwrap() -> Option<String> {
    for path in ["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| "bwrap".to_string())
}

/// Same explicit, development-only opt-out the guardian uses.
#[cfg(target_os = "linux")]
fn unsandboxed_allowed() -> bool {
    std::env::var("SOLARPLEX_ALLOW_UNSANDBOXED").is_ok()
}

/// How a not-yet-approved command may be run for observation.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
enum ScoutMode {
    /// Inside the read-only, network-less bwrap sandbox.
    Sandboxed,
    /// Directly on the host. Only ever via the explicit dev opt-out.
    Unsandboxed,
    /// Not at all: no sandbox and no opt-out means no execution.
    Refuse,
}

/// The one place the run-or-refuse decision is made. A sandbox, when there is
/// one, always wins; its absence is never silently papered over.
#[cfg(any(target_os = "linux", test))]
fn scout_mode(bwrap_available: bool, unsandboxed_opt_out: bool) -> ScoutMode {
    match (bwrap_available, unsandboxed_opt_out) {
        (true, _) => ScoutMode::Sandboxed,
        (false, true) => ScoutMode::Unsandboxed,
        (false, false) => ScoutMode::Refuse,
    }
}

/// bwrap arguments (everything before the `--` that introduces the command).
#[cfg(target_os = "linux")]
fn sandbox_args() -> Vec<String> {
    let mut args: Vec<String> = [
        "--ro-bind",
        "/",
        "/",
        "--size",
        &SCOUT_SCRATCH_BYTES.to_string(),
        "--tmpfs",
        "/tmp",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // An allowlist, not a denylist: only what a command needs to resolve tools
    // and locale. Nothing the shim itself holds (SOLARPLEX_*, tokens, cloud
    // credentials) reaches the scouted command.
    for key in ["PATH", "HOME", "LANG", "LC_ALL", "TZ", "USER", "LOGNAME"] {
        let value = std::env::var(key)
            .ok()
            .or_else(|| (key == "PATH").then(|| "/usr/local/bin:/usr/bin:/bin".to_string()));
        if let Some(v) = value {
            args.extend(["--setenv".to_string(), key.to_string(), v]);
        }
    }
    args
}

/// Restrict the strace process (and so, by inheritance, everything it starts)
/// before exec: bounded CPU, bounded file size, no core dumps.
#[cfg(target_os = "linux")]
fn limit_resources(timeout_secs: u64) -> std::io::Result<()> {
    // `resource as _`: the parameter's type differs between glibc and musl.
    fn set(resource: libc::c_int, soft: u64) -> std::io::Result<()> {
        let lim = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: soft as libc::rlim_t,
        };
        if unsafe { libc::setrlimit(resource as _, &lim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    set(
        libc::RLIMIT_CPU as libc::c_int,
        timeout_secs.saturating_add(5),
    )?;
    set(libc::RLIMIT_FSIZE as libc::c_int, SCOUT_SCRATCH_BYTES)?;
    set(libc::RLIMIT_CORE as libc::c_int, 0)?;
    Ok(())
}

/// Reduce an strace log of the *whole* sandbox launch (bwrap's own setup
/// included) to what the scouted command did.
///
/// bwrap builds mounts and namespaces before it execs the command, and strace
/// (outside it) records all of that: opens of `/proc/self/uid_map`, mount
/// points, libraries. Left in, it would be read as the command's effects and
/// leak into the policy the human approves. Everything up to and including the
/// successful exec of [`INNER_SHELL`] is setup; keep the exec itself (it is the
/// command, subprocess #1) and everything after it, minus any process that was
/// already running during setup (bwrap's own).
///
/// `None` means the command never started: bwrap or strace failed (no user
/// namespaces, ptrace denied, ...), and there is nothing to learn from.
#[cfg(any(target_os = "linux", test))]
fn inside_sandbox(log: &str) -> Option<String> {
    let marker_prefix = format!("execve(\"{INNER_SHELL_PATH}\", [\"{INNER_SHELL_PATH}\", \"-c\", ");
    let lines: Vec<&str> = log.lines().collect();
    let marker = lines.iter().position(|l| {
        let call = strip_pid_prefix(l);
        call.starts_with(&marker_prefix) && !is_failed_syscall(call)
    })?;
    let marker_pid = pid_of(lines[marker]);
    let setup_pids: std::collections::HashSet<&str> = lines[..marker]
        .iter()
        .filter_map(|l| pid_of(l))
        .filter(|p| Some(*p) != marker_pid)
        .collect();
    let kept: Vec<&str> = lines[marker..]
        .iter()
        .copied()
        .filter(|l| pid_of(l).is_none_or(|p| !setup_pids.contains(p)))
        .collect();
    Some(kept.join("\n"))
}

/// Shell the sandbox execs. Absolute, so the exec is unambiguous in the strace
/// log (no PATH-search noise), and it doubles as the marker for "bwrap's setup
/// is over". Shared by the launcher and the log filter so the two cannot drift.
#[cfg(any(target_os = "linux", test))]
const INNER_SHELL_PATH: &str = "/bin/sh";

/// The pid at the start of a strace `-f` line: `1234  openat(...)` or
/// `[pid  1234] openat(...)`.
#[cfg(any(target_os = "linux", test))]
fn pid_of(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if let Some(rest) = line.strip_prefix("[pid") {
        let rest = rest.trim_start();
        let end = rest.find(']')?;
        return Some(rest[..end].trim());
    }
    let end = line.find(|c: char| !c.is_ascii_digit())?;
    (end > 0).then(|| &line[..end])
}

#[cfg(target_os = "linux")]
async fn run_scout_linux(command: &str, timeout_secs: u64) -> ScoutManifest {
    use std::process::Stdio;
    use std::time::Instant;
    use tokio::process::Command;

    let unavailable = |why: &str| {
        tracing::warn!("scout: {why}");
        ScoutManifest {
            command: command.to_string(),
            sandbox_backend: "none".to_string(),
            ..Default::default()
        }
    };

    if Command::new("strace")
        .arg("--version")
        .output()
        .await
        .is_err()
    {
        return unavailable("strace is not available; no prediction for this command");
    }

    // Decide HOW this not-yet-approved command may run, before anything runs.
    let bwrap = find_bwrap();
    let backend = match scout_mode(bwrap.is_some(), unsandboxed_allowed()) {
        ScoutMode::Sandboxed => SCOUT_BACKEND_SANDBOXED,
        ScoutMode::Unsandboxed => {
            tracing::warn!(
                "scout: bwrap unavailable, running the command UNSANDBOXED before approval \
                 (SOLARPLEX_ALLOW_UNSANDBOXED is set; development only, not safe for production)"
            );
            SCOUT_BACKEND_UNSANDBOXED
        }
        ScoutMode::Refuse => {
            return unavailable(
                "bwrap is not available: refusing to run an unapproved command unsandboxed \
                 (set SOLARPLEX_ALLOW_UNSANDBOXED=1 to override; development only)",
            );
        }
    };

    let id = ulid::Ulid::new();
    let tmp = format!("/tmp/solarplex_scout_{id}.log");
    let tmp_err = format!("/tmp/solarplex_scout_{id}.err");
    // The scouted command's own output is discarded; strace/bwrap diagnostics
    // go to a file so a failed launch can be explained.
    let err_file = std::fs::File::create(&tmp_err).ok();

    let mut cmd = Command::new("strace");
    cmd.args([
        "-f",
        "-s",
        "256",
        "-e",
        "trace=openat,unlinkat,unlink,renameat,rename,connect,execve",
        "-o",
        &tmp,
        "--",
    ]);
    match &bwrap {
        Some(bw) => {
            cmd.arg(bw);
            cmd.args(sandbox_args());
            cmd.args(["--", INNER_SHELL_PATH, "-c", command]);
        }
        None => {
            cmd.args(["sh", "-c", command]);
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(err_file.map(Stdio::from).unwrap_or_else(Stdio::null))
        .kill_on_drop(true);
    unsafe {
        cmd.pre_exec(move || limit_resources(timeout_secs));
    }

    let t0 = Instant::now();
    let timed_out =
        tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), cmd.status())
            .await
            .is_err();

    let duration_ms = t0.elapsed().as_millis() as u64;
    let raw_log = tokio::fs::read_to_string(&tmp).await.unwrap_or_default();
    let stderr_head: String = tokio::fs::read_to_string(&tmp_err)
        .await
        .unwrap_or_default()
        .chars()
        .take(400)
        .collect();
    let _ = tokio::fs::remove_file(&tmp).await;
    let _ = tokio::fs::remove_file(&tmp_err).await;

    let log = if bwrap.is_some() {
        match inside_sandbox(&raw_log) {
            Some(l) => l,
            None => {
                tracing::warn!(
                    stderr = %stderr_head.trim(),
                    "scout: the sandbox never started the command (user namespaces or ptrace \
                     unavailable?); no prediction for this command"
                );
                return ScoutManifest {
                    command: command.to_string(),
                    sandbox_backend: "none".to_string(),
                    duration_ms,
                    truncated: timed_out,
                    ..Default::default()
                };
            }
        }
    } else {
        raw_log
    };

    let (mut reads, file_events, mut connects, mut execs) = parse_strace_output(&log);
    reads.sort_unstable();
    reads.dedup();
    connects.sort_unstable();
    connects.dedup();
    execs.sort_unstable();
    execs.dedup();

    let mut effect_map: HashMap<String, FileOps> = HashMap::new();
    for fe in file_events {
        effect_map.entry(fe.path).or_default().merge(&fe.ops);
    }
    // One stat pass per unique path, taken as of scout completion -- the
    // identity `sandbox_entry.rs` will re-check immediately before granting
    // the corresponding landlock rule, seconds from now after the human has
    // approved. `None` for a path that doesn't exist yet (a pure `create`):
    // nothing to pin an identity to, and that's fine, there's nothing for a
    // TOCTOU swap to exploit on a path with no prior object at it.
    let mut file_effects: Vec<FileEvent> = Vec::with_capacity(effect_map.len());
    for (path, ops) in effect_map {
        let identity = tokio::fs::metadata(&path).await.ok().map(|m| {
            (
                std::os::unix::fs::MetadataExt::dev(&m),
                std::os::unix::fs::MetadataExt::ino(&m),
            )
        });
        file_effects.push(FileEvent {
            path,
            ops,
            identity,
        });
    }
    file_effects.sort_by(|a, b| a.path.cmp(&b.path));

    let total = reads.len() + file_effects.len() + connects.len() + execs.len();
    let truncated = timed_out || total >= MAX_EVENTS;

    ScoutManifest {
        command: command.to_string(),
        file_reads: reads,
        file_effects,
        network_connects: connects,
        subprocesses: execs,
        duration_ms,
        sandbox_backend: backend.to_string(),
        truncated,
    }
}

fn parse_strace_output(content: &str) -> (Vec<String>, Vec<FileEvent>, Vec<String>, Vec<String>) {
    let mut reads = Vec::new();
    let mut effects = Vec::new();
    let mut connects = Vec::new();
    let mut execs = Vec::new();
    let mut count = 0usize;

    for line in content.lines() {
        if count >= MAX_EVENTS {
            break;
        }
        let call = strip_pid_prefix(line);
        if call.starts_with("openat(") {
            if let Some((path, ops)) = parse_openat(call) {
                if !is_noise(&path) {
                    if ops.any() {
                        effects.push(FileEvent {
                            path,
                            ops,
                            identity: None,
                        });
                    } else {
                        reads.push(path);
                    }
                    count += 1;
                }
            }
        } else if call.starts_with("unlinkat(") || call.starts_with("unlink(") {
            if let Some(path) = parse_unlink(call) {
                if !is_noise(&path) {
                    effects.push(FileEvent {
                        path,
                        ops: FileOps {
                            delete: true,
                            ..Default::default()
                        },
                        identity: None,
                    });
                    count += 1;
                }
            }
        } else if call.starts_with("renameat(") || call.starts_with("rename(") {
            if let Some((src, dst)) = parse_rename(call) {
                if !is_noise(&src) {
                    effects.push(FileEvent {
                        path: src,
                        ops: FileOps {
                            rename: true,
                            delete: true,
                            ..Default::default()
                        },
                        identity: None,
                    });
                    count += 1;
                }
                if !is_noise(&dst) {
                    effects.push(FileEvent {
                        path: dst,
                        ops: FileOps {
                            rename: true,
                            create: true,
                            ..Default::default()
                        },
                        identity: None,
                    });
                    count += 1;
                }
            }
        } else if call.starts_with("connect(") {
            if let Some(addr) = parse_connect(call) {
                connects.push(addr);
                count += 1;
            }
        } else if call.starts_with("execve(") {
            if let Some(exe) = parse_execve(call) {
                if !is_noise(&exe) {
                    execs.push(exe);
                    count += 1;
                }
            }
        }
    }
    (reads, effects, connects, execs)
}

fn is_noise(path: &str) -> bool {
    NOISE_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn strip_pid_prefix(line: &str) -> &str {
    let line = line.trim_start();
    if line.starts_with('[') {
        if let Some(b) = line.find(']') {
            return line[b + 1..].trim_start();
        }
    }
    line.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ')
}

// ── Quoted-string arguments ─────────────────────────────────────────────────
//
// strace renders a path/exec-arg string the same way a C string literal is
// written: wrapped in `"..."`, with `\"` for a literal quote, `\\` for a
// literal backslash, and `\n`/`\t`/`\r` for the common control characters.
// The previous version of every parser below found the string's extent with
// `s.find('"')` for the open and `s[q1..].find('"')` for the close -- with
// no concept of escaping, an escaped quote inside the real path (e.g. a
// file literally named `foo"bar`, which strace renders as `"foo\"bar"`) was
// indistinguishable from the real closing quote, silently truncating the
// path right there. Since this scout's whole job is building the sandbox's
// `DeclaredEffects` policy from what it observed, a truncated path here
// means the policy gets built from the wrong path -- a correctness bug with
// real consequences, not just an edge case.

/// One backslash-escape. Unrecognized escapes are kept as a literal
/// two-character sequence rather than guessed at -- an escape this parser
/// doesn't know about can then never silently change the string's meaning,
/// unlike the old bug where an escaped quote silently changed where the
/// string was read to end.
fn escaped_char(input: &str) -> nom::IResult<&str, String> {
    use nom::character::complete::{anychar, char};
    use nom::sequence::preceded;
    use nom::Parser;
    let (rest, c) = preceded(char('\\'), anychar).parse(input)?;
    let resolved = match c {
        '"' => "\"".to_string(),
        '\\' => "\\".to_string(),
        'n' => "\n".to_string(),
        't' => "\t".to_string(),
        'r' => "\r".to_string(),
        other => format!("\\{other}"),
    };
    Ok((rest, resolved))
}

/// Parses one strace-quoted string argument out of `input`, skipping over
/// anything before the opening quote (the syscall name and any preceding
/// args, same as the old code's `s.find('"')`), and returns the unescaped
/// content plus everything after the closing quote.
fn quoted_string(input: &str) -> nom::IResult<&str, String> {
    use nom::branch::alt;
    use nom::bytes::complete::{is_not, take_until};
    use nom::character::complete::char;
    use nom::combinator::map;
    use nom::multi::fold_many0;
    use nom::sequence::delimited;
    use nom::Parser;

    let (input, _) = take_until("\"").parse(input)?;
    delimited(
        char('"'),
        fold_many0(
            alt((map(is_not("\"\\"), |s: &str| s.to_string()), escaped_char)),
            String::new,
            |mut acc, piece| {
                acc.push_str(&piece);
                acc
            },
        ),
        char('"'),
    )
    .parse(input)
}

fn parse_openat(s: &str) -> Option<(String, FileOps)> {
    let ops = FileOps {
        create: s.contains("O_CREAT"),
        write: s.contains("O_WRONLY") || s.contains("O_RDWR") || s.contains("O_TRUNC"),
        delete: false,
        rename: false,
    };
    // A failed open is normally noise (probing library paths that don't
    // exist). A *write* refused by the scout's read-only sandbox is not: it is
    // the command saying what it means to change, and that intent is exactly
    // what the policy is built from. Failed reads stay dropped.
    if is_failed_syscall(s) && !(ops.any() && failed_with(s, DENIED_ERRNOS)) {
        return None;
    }
    let (_, path) = quoted_string(s).ok()?;
    if path.is_empty() {
        return None;
    }
    Some((path, ops))
}

fn parse_unlink(s: &str) -> Option<String> {
    if is_failed_syscall(s) && !failed_with(s, DENIED_ERRNOS) {
        return None;
    }
    let (_, path) = quoted_string(s).ok()?;
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

fn parse_rename(s: &str) -> Option<(String, String)> {
    if is_failed_syscall(s) && !failed_with(s, DENIED_ERRNOS) {
        return None;
    }
    let (rest, src) = quoted_string(s).ok()?;
    let (_, dst) = quoted_string(rest).ok()?;
    if src.is_empty() || dst.is_empty() {
        None
    } else {
        Some((src, dst))
    }
}

fn parse_connect(s: &str) -> Option<String> {
    // In the scout's network-less sandbox every connect fails; the attempt is
    // the observation. (`EINPROGRESS` is a normal non-blocking connect.)
    if is_failed_syscall(s) && !failed_with(s, CONNECT_INTENT_ERRNOS) {
        return None;
    }
    if s.contains("AF_UNIX") || s.contains("AF_NETLINK") {
        return None;
    }
    let marker = "sin_addr=inet_addr(\"";
    let start = s.find(marker)? + marker.len();
    let end = s[start..].find('"')? + start;
    let ip = s[start..end].to_string();
    let pm = "sin_port=htons(";
    let ps = s.find(pm)? + pm.len();
    let pe = s[ps..].find(')')? + ps;
    Some(format!("{ip}:{}", &s[ps..pe]))
}

fn parse_execve(s: &str) -> Option<String> {
    if is_failed_syscall(s) {
        return None;
    }
    let (_, path) = quoted_string(s).ok()?;
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

fn is_failed_syscall(s: &str) -> bool {
    s.rfind(" = ")
        .map(|i| s[i + 3..].trim().starts_with('-'))
        .unwrap_or(false)
}

/// Errnos that mean "the sandbox (or the filesystem's own permissions)
/// refused a modification", as opposed to "that path doesn't exist".
const DENIED_ERRNOS: &[&str] = &["EROFS", "EACCES", "EPERM"];

/// Errnos a connect returns when it was attempted but couldn't go anywhere,
/// e.g. inside a network namespace with no routes.
const CONNECT_INTENT_ERRNOS: &[&str] = &[
    "ENETUNREACH",
    "EHOSTUNREACH",
    "ENETDOWN",
    "ECONNREFUSED",
    "EINPROGRESS",
    "EACCES",
    "EPERM",
];

/// The errno name of a failed strace line: `... = -1 EROFS (Read-only file
/// system)` gives `Some("EROFS")`.
fn failure_errno(s: &str) -> Option<&str> {
    let i = s.rfind(" = -")?;
    let rest = s[i + 4..].trim_start_matches(|c: char| c.is_ascii_digit());
    rest.split_whitespace().next()
}

fn failed_with(s: &str, errnos: &[&str]) -> bool {
    failure_errno(s).is_some_and(|e| errnos.contains(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openat_extracts_path_and_flags() {
        let line = r#"openat(AT_FDCWD, "/home/user/file.txt", O_RDONLY) = 3"#;
        let (path, ops) = parse_openat(line).expect("should parse");
        assert_eq!(path, "/home/user/file.txt");
        assert!(!ops.write);
        assert!(!ops.create);
    }

    #[test]
    fn openat_extracts_write_and_create_flags() {
        let line = r#"openat(AT_FDCWD, "/tmp/out.log", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4"#;
        let (path, ops) = parse_openat(line).expect("should parse");
        assert_eq!(path, "/tmp/out.log");
        assert!(ops.write);
        assert!(ops.create);
    }

    #[test]
    fn openat_returns_none_on_failed_syscall() {
        let line = r#"openat(AT_FDCWD, "/root/secret", O_RDONLY) = -1 EACCES (Permission denied)"#;
        assert!(parse_openat(line).is_none());
    }

    /// The actual bug: a path containing a literal `"` comes out of strace
    /// as `\"` inside the quotes. The old `s.find('"')`-based parser had no
    /// concept of this and truncated the path at the escaped quote instead
    /// of the real closing one.
    #[test]
    fn openat_handles_escaped_quote_in_path_without_truncating() {
        let line = r#"openat(AT_FDCWD, "/tmp/foo\"bar/file.txt", O_RDONLY) = 3"#;
        let (path, _) = parse_openat(line).expect("should parse");
        assert_eq!(path, "/tmp/foo\"bar/file.txt");
    }

    #[test]
    fn openat_handles_escaped_backslash_in_path() {
        let line = r#"openat(AT_FDCWD, "/tmp/foo\\bar", O_RDONLY) = 3"#;
        let (path, _) = parse_openat(line).expect("should parse");
        assert_eq!(path, "/tmp/foo\\bar");
    }

    #[test]
    fn unlink_extracts_path() {
        let line = r#"unlinkat(AT_FDCWD, "/tmp/stale.lock", 0) = 0"#;
        assert_eq!(parse_unlink(line).as_deref(), Some("/tmp/stale.lock"));
    }

    #[test]
    fn rename_extracts_both_paths_even_with_an_escaped_quote_in_the_first() {
        let line = r#"renameat(AT_FDCWD, "/tmp/a\"b", AT_FDCWD, "/tmp/c") = 0"#;
        let (src, dst) = parse_rename(line).expect("should parse");
        assert_eq!(src, "/tmp/a\"b");
        assert_eq!(dst, "/tmp/c");
    }

    #[test]
    fn execve_extracts_the_executable_path() {
        let line = r#"execve("/usr/bin/curl", ["curl", "-s", "http://example.com"], 0x7ffd) = 0"#;
        assert_eq!(parse_execve(line).as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn connect_extracts_ip_and_port() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0"#;
        assert_eq!(parse_connect(line).as_deref(), Some("93.184.216.34:443"));
    }

    #[test]
    fn connect_ignores_af_unix() {
        let line = r#"connect(3, {sa_family=AF_UNIX, sun_path="/run/foo.sock"}, 110) = 0"#;
        assert!(parse_connect(line).is_none());
    }

    #[test]
    fn is_noise_matches_configured_prefixes() {
        assert!(is_noise("/proc/self/status"));
        assert!(is_noise("/etc/ld.so.cache"));
        assert!(!is_noise("/home/user/project/main.rs"));
    }

    #[test]
    fn strip_pid_prefix_handles_multiprocess_format() {
        assert_eq!(
            strip_pid_prefix("[pid 12345] openat(AT_FDCWD"),
            "openat(AT_FDCWD"
        );
        assert_eq!(strip_pid_prefix("openat(AT_FDCWD"), "openat(AT_FDCWD");
    }

    #[test]
    fn parse_strace_output_end_to_end_with_an_escaped_quote() {
        let log = "openat(AT_FDCWD, \"/tmp/weird\\\"name.txt\", O_RDONLY) = 3\n\
                    openat(AT_FDCWD, \"/tmp/out.log\", O_WRONLY|O_CREAT, 0644) = 4\n";
        let (reads, effects, _connects, _execs) = parse_strace_output(log);
        assert_eq!(reads, vec!["/tmp/weird\"name.txt".to_string()]);
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].path, "/tmp/out.log");
        assert!(effects[0].ops.create);
    }

    // ── Intent: refused writes and connects still count ──────────────────────
    //
    // The scout runs read-only and network-less, so everything it observes
    // that would change the world is *refused*. The policy is built from what
    // the command tried to do, so a refusal must not erase the attempt, while
    // an ordinary failed lookup (nothing there) must still be ignored.

    #[test]
    fn a_write_refused_by_the_sandbox_is_recorded_as_intent() {
        let line = r#"openat(AT_FDCWD, "/home/u/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EROFS (Read-only file system)"#;
        let (path, ops) = parse_openat(line).expect("refused write is intent");
        assert_eq!(path, "/home/u/out.txt");
        assert!(ops.write && ops.create);
    }

    #[test]
    fn a_write_denied_by_permissions_is_recorded_as_intent() {
        let line =
            r#"openat(AT_FDCWD, "/etc/hosts", O_WRONLY|O_APPEND) = -1 EACCES (Permission denied)"#;
        assert_eq!(parse_openat(line).expect("intent").0, "/etc/hosts");
    }

    #[test]
    fn a_write_to_a_missing_path_is_still_dropped() {
        let line = r#"openat(AT_FDCWD, "/no/such/dir/f", O_WRONLY|O_CREAT, 0666) = -1 ENOENT (No such file or directory)"#;
        assert!(parse_openat(line).is_none());
    }

    #[test]
    fn a_refused_read_is_still_dropped() {
        let line =
            r#"openat(AT_FDCWD, "/root/secret", O_RDONLY) = -1 EROFS (Read-only file system)"#;
        assert!(parse_openat(line).is_none());
    }

    #[test]
    fn a_refused_unlink_and_rename_are_recorded_as_intent() {
        let rm = r#"unlinkat(AT_FDCWD, "/home/u/precious", 0) = -1 EROFS (Read-only file system)"#;
        assert_eq!(parse_unlink(rm).as_deref(), Some("/home/u/precious"));
        let mv = r#"renameat(AT_FDCWD, "/home/u/a", AT_FDCWD, "/home/u/b") = -1 EROFS (Read-only file system)"#;
        assert_eq!(
            parse_rename(mv),
            Some(("/home/u/a".to_string(), "/home/u/b".to_string()))
        );
        let gone =
            r#"unlinkat(AT_FDCWD, "/home/u/missing", 0) = -1 ENOENT (No such file or directory)"#;
        assert!(parse_unlink(gone).is_none());
    }

    #[test]
    fn a_connect_with_nowhere_to_go_is_recorded_as_intent() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH (Network is unreachable)"#;
        assert_eq!(parse_connect(line).as_deref(), Some("203.0.113.9:80"));
        let refused = r#"connect(3, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)"#;
        assert_eq!(parse_connect(refused).as_deref(), Some("127.0.0.1:5432"));
        let bad = r#"connect(99, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 EBADF (Bad file descriptor)"#;
        assert!(
            parse_connect(bad).is_none(),
            "an unrelated failure is not intent"
        );
    }

    #[test]
    fn failure_errno_extracts_the_name() {
        assert_eq!(
            failure_errno("x = -1 EROFS (Read-only file system)"),
            Some("EROFS")
        );
        assert_eq!(failure_errno("x = 3"), None);
    }

    // ── Sandbox setup noise ──────────────────────────────────────────────────
    //
    // Shaped like a real capture of `strace -f -- bwrap ... -- /bin/sh -c ...`:
    // bwrap (pid 3956) and its child (3960) do their setup, then 3960 execs
    // the shell, which runs the command. Only the latter is the command.

    const SANDBOX_LOG: &str = concat!(
        "3956  execve(\"/usr/bin/bwrap\", [\"bwrap\", \"--ro-bind\", \"/\", \"/\", \"--\", \"/bin/sh\", \"-c\", \"echo hi\"], 0x7ffc /* 32 vars */) = 0\n",
        "3956  openat(AT_FDCWD, \"/lib/x86_64-linux-gnu/libselinux.so.1\", O_RDONLY|O_CLOEXEC) = 3\n",
        "3956  openat(AT_FDCWD, \"/proc/self/uid_map\", O_RDWR) = 4\n",
        "3956  openat(AT_FDCWD, \"/tmp/bwrap-setup-mount-point\", O_WRONLY|O_CREAT, 0600) = 5\n",
        "3960  openat(AT_FDCWD, \"/newroot/dev/null\", O_RDWR) = 6\n",
        "3960  execve(\"/bin/sh\", [\"/bin/sh\", \"-c\", \"echo hi > /tmp/a; cat /etc/hostname\"], 0x5dc9 /* 3 vars */) = 0\n",
        "3960  openat(AT_FDCWD, \"/tmp/a\", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3\n",
        "3960  openat(AT_FDCWD, \"/home/u/x.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EROFS (Read-only file system)\n",
        "3961  execve(\"/usr/bin/cat\", [\"cat\", \"/etc/hostname\"], 0x5dc9 /* 3 vars */) = 0\n",
        "3961  openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY) = 3\n",
        "3956  openat(AT_FDCWD, \"/bwrap/parent/after/exec\", O_RDWR) = 5\n",
    );

    #[test]
    fn inside_sandbox_drops_bwraps_own_setup_and_keeps_the_command() {
        let inside = inside_sandbox(SANDBOX_LOG).expect("marker present");
        for leaked in [
            "bwrap",
            "libselinux",
            "uid_map",
            "mount-point",
            "/newroot",
            "/bwrap/parent/after/exec",
        ] {
            assert!(!inside.contains(leaked), "setup noise leaked: {leaked}");
        }
        let (reads, effects, _c, execs) = parse_strace_output(&inside);
        assert_eq!(
            execs,
            vec!["/bin/sh".to_string(), "/usr/bin/cat".to_string()]
        );
        assert_eq!(reads, vec!["/etc/hostname".to_string()]);
        let paths: Vec<&str> = effects.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/tmp/a", "/home/u/x.txt"]);
    }

    #[test]
    fn inside_sandbox_is_none_when_the_command_never_started() {
        let only_setup = "3956  execve(\"/usr/bin/bwrap\", [\"bwrap\"], 0x7ffc) = 0\n\
                          3956  openat(AT_FDCWD, \"/proc/filesystems\", O_RDONLY) = 3\n";
        assert!(inside_sandbox(only_setup).is_none());
    }

    #[test]
    fn a_failed_exec_of_the_shell_is_not_the_marker() {
        let log = "3960  execve(\"/bin/sh\", [\"/bin/sh\", \"-c\", \"x\"], 0x1) = -1 ENOENT (No such file or directory)\n";
        assert!(inside_sandbox(log).is_none());
    }

    #[test]
    fn pid_of_handles_both_strace_formats() {
        assert_eq!(pid_of("3960  execve(\"/bin/sh\""), Some("3960"));
        assert_eq!(pid_of("[pid  3960] execve(\"/bin/sh\""), Some("3960"));
        assert_eq!(pid_of("execve(\"/bin/sh\""), None);
    }

    // ── The run-or-refuse decision ───────────────────────────────────────────

    #[test]
    fn no_sandbox_and_no_opt_out_means_the_command_is_never_run() {
        assert_eq!(scout_mode(true, false), ScoutMode::Sandboxed);
        assert_eq!(
            scout_mode(true, true),
            ScoutMode::Sandboxed,
            "a sandbox always wins"
        );
        assert_eq!(scout_mode(false, true), ScoutMode::Unsandboxed);
        assert_eq!(scout_mode(false, false), ScoutMode::Refuse);
    }

    #[test]
    fn the_sandbox_environment_is_an_allowlist_and_the_filesystem_is_read_only() {
        let args = sandbox_args();
        assert!(args.contains(&"--clearenv".to_string()));

        // Every variable passed in must be on the allowlist, whatever the
        // shim's own environment happens to contain.
        let allowed = ["PATH", "HOME", "LANG", "LC_ALL", "TZ", "USER", "LOGNAME"];
        let passed: Vec<&str> = args
            .windows(3)
            .filter(|w| w[0] == "--setenv")
            .map(|w| w[1].as_str())
            .collect();
        assert!(!passed.is_empty(), "PATH at least must be set");
        for key in &passed {
            assert!(
                allowed.contains(key),
                "{key} is not on the scout env allowlist"
            );
        }

        let joined = args.join(" ");
        assert!(
            joined.contains("--unshare-net"),
            "the sandbox must have no network"
        );
        assert!(
            joined.contains("--ro-bind / /"),
            "the root must be read-only"
        );
        assert!(
            joined.contains("--die-with-parent"),
            "a killed scout must take its tree with it"
        );
    }

    // ── Real sandbox, real strace ────────────────────────────────────────────
    //
    // These run the actual scout. They skip (loudly) where bwrap, strace, or
    // unprivileged user namespaces aren't available (e.g. some CI runners), so
    // `cargo test` stays green everywhere while still proving the property on
    // any machine that can run the real thing.

    #[cfg(target_os = "linux")]
    async fn sandbox_works() -> bool {
        let probe = run_scout("true", 15).await;
        let ok = probe.sandbox_backend == SCOUT_BACKEND_SANDBOXED;
        if !ok {
            eprintln!(
                "SKIPPING real-sandbox scout test: backend was {:?} (need strace + bwrap + user namespaces)",
                probe.sandbox_backend
            );
        }
        ok
    }

    #[cfg(target_os = "linux")]
    fn have(bin: &str) -> bool {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
            .unwrap_or(false)
    }

    /// The point of the whole change: a command scouted BEFORE approval must
    /// not be able to change anything real, yet its intent must still show up.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_scout_cannot_change_anything_but_still_reports_what_it_tried() {
        if !sandbox_works().await {
            return;
        }
        let home = std::env::var("HOME").expect("HOME");
        let run = ulid::Ulid::new();
        let new_file = format!("{home}/.solarplex_scout_probe_{run}");
        let victim = format!("{home}/.solarplex_scout_victim_{run}");
        let tmp_file = format!("/tmp/solarplex_scout_tmp_probe_{run}");
        std::fs::write(&victim, b"must survive").expect("seed victim file");

        let net = if have("bash") {
            "bash -c 'exec 3<>/dev/tcp/203.0.113.9/80' 2>/dev/null;"
        } else {
            ""
        };
        let cmd = format!(
            "echo x > {new_file}; rm -f {victim}; echo y > {tmp_file}; cat /etc/hostname; {net} true"
        );
        let m = run_scout(&cmd, 20).await;

        // SAFETY: nothing real changed.
        let created = std::path::Path::new(&new_file).exists();
        let victim_intact =
            std::fs::read(&victim).ok().as_deref() == Some(b"must survive".as_slice());
        let tmp_leaked = std::path::Path::new(&tmp_file).exists();
        let _ = std::fs::remove_file(&new_file);
        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_file(&tmp_file);
        assert!(!created, "the scouted command created a real file");
        assert!(
            victim_intact,
            "the scouted command deleted or changed a real file"
        );
        assert!(!tmp_leaked, "the sandbox's /tmp leaked onto the host");

        // FIDELITY: the intent is still in the manifest.
        assert_eq!(m.sandbox_backend, SCOUT_BACKEND_SANDBOXED);
        let find = |p: &str| m.file_effects.iter().find(|e| e.path == p);
        let created_fx = find(&new_file).expect("refused create must be reported");
        assert!(created_fx.ops.create && created_fx.ops.write);
        assert!(
            find(&victim).is_some_and(|e| e.ops.delete),
            "refused delete must be reported"
        );
        assert!(
            find(&tmp_file).is_some(),
            "write to the private /tmp is reported"
        );
        if have("bash") {
            assert!(
                m.network_connects.iter().any(|c| c == "203.0.113.9:80"),
                "attempted connect must be reported: {:?}",
                m.network_connects
            );
        }

        // NOISE: bwrap's own setup is not the command's behavior.
        assert!(
            !m.subprocesses.iter().any(|s| s.contains("bwrap")),
            "bwrap leaked into subprocesses: {:?}",
            m.subprocesses
        );
        assert!(m.subprocesses.iter().any(|s| s == "/bin/sh"));
        assert!(
            !m.file_effects
                .iter()
                .any(|e| e.path.starts_with("/proc") || e.path.contains("bwrap")),
            "setup writes leaked into effects: {:?}",
            m.file_effects.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
    }

    /// Nothing from the shim's own environment outside the allowlist may reach
    /// the scouted command. Uses a variable cargo itself puts in every test
    /// process's environment (so the test needs no `set_var`, which would race
    /// with other test threads), and observes it via the strace log: the
    /// command only touches the probe path if it can see the variable.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_scouted_command_cannot_see_the_shims_environment() {
        if !sandbox_works().await {
            return;
        }
        if std::env::var_os("CARGO_MANIFEST_DIR").is_none() {
            eprintln!("SKIPPING: CARGO_MANIFEST_DIR not set (run via `cargo test`)");
            return;
        }
        let probe = format!("/tmp/solarplex_env_probe_{}", ulid::Ulid::new());
        let cmd = format!("[ -n \"$CARGO_MANIFEST_DIR\" ] && echo leak > {probe}; true");
        let m = run_scout(&cmd, 20).await;
        assert_eq!(m.sandbox_backend, SCOUT_BACKEND_SANDBOXED);
        assert!(
            !m.file_effects.iter().any(|e| e.path == probe),
            "an environment variable outside the allowlist was visible inside the scout sandbox"
        );
    }

    /// A scout that times out must take everything it started with it. (The
    /// previous implementation dropped the future without killing the child,
    /// so a long-running scouted command kept running on the host.)
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_timed_out_scout_leaves_no_processes_behind() {
        if !sandbox_works().await {
            return;
        }
        let needle = b"sleep\x0031337\x00";
        let survivors = || -> Vec<i32> {
            std::fs::read_dir("/proc")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
                .filter(|pid| {
                    std::fs::read(format!("/proc/{pid}/cmdline"))
                        .map(|c| c == needle)
                        .unwrap_or(false)
                })
                .collect()
        };
        assert!(survivors().is_empty(), "stale sleep from an earlier run");

        let m = run_scout("sleep 31337 & sleep 31337; true", 2).await;
        assert!(m.truncated, "a timed-out scout must be marked truncated");

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let left = survivors();
        for pid in &left {
            unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
        assert!(
            left.is_empty(),
            "scout timeout left processes running: {left:?}"
        );
    }
}

// ── Bounded issue pool ────────────────────────────────────────────────────────

pub struct ScoutJob {
    pub command: String,
    pub approval_id: String,
    pub session: Arc<crate::session::SessionClient>,
    pub result_tx: oneshot::Sender<ScoutManifest>,
}

#[derive(Clone, Debug)]
pub struct CategoryConfig {
    pub width: usize,
    pub queue: usize,
}

#[derive(Clone, Debug)]
pub struct ScoutPoolConfig {
    pub default_width: usize,
    pub default_queue: usize,
    pub categories: HashMap<String, CategoryConfig>,
    pub timeout_secs: u64,
}

impl Default for ScoutPoolConfig {
    fn default() -> Self {
        Self {
            default_width: 4,
            default_queue: 64,
            categories: HashMap::new(),
            timeout_secs: 20,
        }
    }
}

#[derive(Clone)]
struct SubPool {
    tx: mpsc::Sender<ScoutJob>,
}

impl SubPool {
    fn spawn(workers: usize, queue: usize, timeout_secs: u64) -> Self {
        let (tx, rx) = mpsc::channel::<ScoutJob>(queue);
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..workers.max(1) {
            let rx = rx.clone();
            tokio::spawn(async move {
                loop {
                    let job = rx.lock().await.recv().await;
                    let Some(job) = job else { break };
                    let manifest = run_scout(&job.command, timeout_secs).await;
                    job.session
                        .patch_approval_scout(&job.approval_id, &manifest)
                        .await;
                    let declared = protocol::effects::DeclaredEffects::from_scout(&manifest);
                    job.session
                        .patch_approval_declared_effects(&job.approval_id, &declared)
                        .await;
                    let _ = job.result_tx.send(manifest);
                }
            });
        }
        Self { tx }
    }

    fn try_send(&self, job: ScoutJob) -> bool {
        self.tx.try_send(job).is_ok()
    }
}

#[derive(Clone)]
pub struct ScoutPool {
    default: SubPool,
    named: HashMap<String, SubPool>,
}

impl ScoutPool {
    pub fn spawn(cfg: &ScoutPoolConfig) -> Self {
        let default = SubPool::spawn(cfg.default_width, cfg.default_queue, cfg.timeout_secs);
        let named = cfg
            .categories
            .iter()
            .map(|(name, cat)| {
                (
                    name.clone(),
                    SubPool::spawn(cat.width, cat.queue, cfg.timeout_secs),
                )
            })
            .collect();
        Self { default, named }
    }

    pub fn try_dispatch(
        &self,
        command: String,
        approval_id: String,
        session: Arc<crate::session::SessionClient>,
        category: Option<&str>,
    ) -> Option<oneshot::Receiver<ScoutManifest>> {
        let (result_tx, result_rx) = oneshot::channel();
        let job = ScoutJob {
            command,
            approval_id,
            session,
            result_tx,
        };
        let pool = category
            .and_then(|c| self.named.get(c))
            .unwrap_or(&self.default);
        if pool.try_send(job) {
            Some(result_rx)
        } else {
            None
        }
    }
}
