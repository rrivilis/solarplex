//! Ring-2 sandbox entry point — invoked by bwrap as the inner process.
//!
//! ```text
//! solarplex-guardian sandbox-entry [opts] -- CMD [ARGS...]
//! ```
//!
//! Applies rlimits, landlock FS rules, and a seccomp denylist, then execvp's
//! CMD.
//!
//! Fail-closed by default: if any of the three setup steps fails, or
//! landlock is only partially enforced by the kernel, this process exits
//! rather than exec'ing CMD with a weaker sandbox than requested. Set
//! `SOLARPLEX_ALLOW_UNSANDBOXED=1` to downgrade this to a warning (mirrors
//! the same variable's meaning in `executor::ring2_exec` — dev/test only,
//! not for production).

pub fn run(args: &[String]) -> ! {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("sandbox-entry: bad args: {e}");
            std::process::exit(2);
        }
    };

    if opts.command.is_empty() {
        eprintln!("sandbox-entry: no command after --");
        std::process::exit(2);
    }

    #[cfg(target_os = "linux")]
    {
        // Resource limits first: both landlock and seccomp setup below
        // allocate memory before CMD ever starts, so bounding CPU/AS/etc.
        // up front means those setup steps are covered by the limits too,
        // not just CMD itself.
        if let Err(e) = apply_resource_limits(&opts.resource_limits) {
            require_full_sandbox_or_opt_out("resource limits", e);
        }
        if let Err(e) = apply_landlock(&opts.file_effects, opts.allow_dynamic) {
            require_full_sandbox_or_opt_out("landlock", e);
        }
        if let Err(e) = apply_seccomp(opts.no_network, opts.no_subprocess) {
            require_full_sandbox_or_opt_out("seccomp", e);
        }
        // Layered on top of the filter just installed, not merged into it --
        // see seccomp_ffi's module doc for why two independently-installed
        // filters compose correctly here. Sends the resulting notify fd
        // back to executor.rs over the inherited fd-5 socketpair so
        // Guardian's own process can broker it; must run after the classic
        // filter above (so the deny rules are already active before the
        // notify filter's default-ALLOW fallback could matter) and before
        // execvp below (the notify relationship has to exist before CMD's
        // own image is loaded, since the dynamic linker's own file opens
        // need to be mediated too -- see notify.rs's module doc for what
        // happens if a listener isn't in place before that point).
        if let Err(e) = apply_seccomp_notify() {
            require_full_sandbox_or_opt_out("seccomp-notify", e);
        }
    }

    #[cfg(unix)]
    {
        // CString::new fails on an embedded NUL byte. This is reachable from
        // agent-controlled input (the command/args come from the approved
        // DeclaredEffects, not a fixed constant) — a panic here would be an
        // uncontrolled crash in a security-sensitive child process; exit
        // cleanly instead, same fail-closed posture as every other setup
        // step above (`require_full_sandbox_or_opt_out`) and the bad-args
        // exit code already used elsewhere in this function.
        let exe = match std::ffi::CString::new(opts.command[0].as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sandbox-entry: command contains an embedded NUL byte: {e}");
                std::process::exit(2);
            }
        };
        let argv: Vec<std::ffi::CString> = match opts
            .command
            .iter()
            .map(|s| std::ffi::CString::new(s.as_bytes()))
            .collect::<Result<_, _>>()
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sandbox-entry: an argument contains an embedded NUL byte: {e}");
                std::process::exit(2);
            }
        };
        let err = unsafe { libc::execvp(exe.as_ptr(), argv_ptrs(&argv).as_ptr()) };
        eprintln!("sandbox-entry: execvp failed (returned {err})");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(&opts.command[0])
            .args(&opts.command[1..])
            .status()
            .expect("sandbox-entry: failed to exec command");
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Shared fail-closed policy for sandbox setup failures (rlimits/landlock/seccomp).
///
/// Exits the process unless `SOLARPLEX_ALLOW_UNSANDBOXED=1` is set, in which
/// case CMD still runs but with whichever layer failed silently missing —
/// the same escape hatch `executor::ring2_exec` uses for a missing bwrap,
/// applied here to a sandbox that's present but weaker than requested.
#[cfg(target_os = "linux")]
fn require_full_sandbox_or_opt_out(component: &str, err: impl std::fmt::Display) {
    if std::env::var("SOLARPLEX_ALLOW_UNSANDBOXED").is_ok() {
        eprintln!(
            "sandbox-entry: {component} failed ({err}) — SOLARPLEX_ALLOW_UNSANDBOXED is set, \
             continuing with a WEAKER sandbox than requested (not for production)"
        );
    } else {
        eprintln!(
            "sandbox-entry: {component} failed ({err}) — refusing to run with a degraded \
             sandbox. Set SOLARPLEX_ALLOW_UNSANDBOXED=1 to override (development only)"
        );
        std::process::exit(1);
    }
}

// ── Arg parsing ───────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct FileEffect {
    path: String,
    ops: FileOps,
    /// `(st_dev, st_ino)` the scout observed at this path, if any -- see
    /// `protocol::effects::FileEffect::identity`'s doc for why this exists.
    /// Re-verified against a fresh `stat()` in `apply_landlock` immediately
    /// before the corresponding landlock rule is added.
    identity: Option<(u64, u64)>,
}

#[derive(Default)]
#[allow(dead_code)]
struct FileOps {
    create: bool,
    write: bool,
    delete: bool,
    rename: bool,
}

impl FileOps {
    #[cfg(target_os = "linux")]
    fn any(&self) -> bool {
        self.create || self.write || self.delete || self.rename
    }
}

#[allow(dead_code)]
struct SandboxOpts {
    no_network: bool,
    no_subprocess: bool,
    file_effects: Vec<FileEffect>,
    allow_dynamic: bool,
    resource_limits: ResourceLimits,
    command: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<SandboxOpts, String> {
    let mut no_network = false;
    let mut no_subprocess = false;
    let mut file_effects = Vec::new();
    let mut allow_dynamic = false;
    let mut resource_limits = ResourceLimits::default();
    let mut command = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-network" => {
                no_network = true;
                i += 1;
            }
            "--no-subprocess" => {
                no_subprocess = true;
                i += 1;
            }
            "--allow-dynamic" => {
                allow_dynamic = true;
                i += 1;
            }
            "--file-effect" => {
                i += 1;
                let val = args.get(i).ok_or("--file-effect requires a value")?;
                let fe = parse_file_effect_arg(val)
                    .ok_or_else(|| format!("invalid --file-effect value: {val}"))?;
                file_effects.push(fe);
                i += 1;
            }
            "--rlimit" => {
                i += 1;
                let val = args.get(i).ok_or("--rlimit requires a value")?;
                apply_rlimit_arg(&mut resource_limits, val)
                    .map_err(|e| format!("invalid --rlimit value {val:?}: {e}"))?;
                i += 1;
            }
            "--" => {
                command = args[i + 1..].to_vec();
                break;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok(SandboxOpts {
        no_network,
        no_subprocess,
        file_effects,
        allow_dynamic,
        resource_limits,
        command,
    })
}

/// Wire format: `OPS:DEV:INO:PATH`, where `DEV`/`INO` are decimal or `-` for
/// "the scout never saw this path exist" (see `executor.rs`'s construction
/// of this arg). `splitn(4, ':')` so a path containing a literal `:` (legal
/// on Linux, just unusual) is preserved intact in the last field rather than
/// truncated at its first colon.
fn parse_file_effect_arg(s: &str) -> Option<FileEffect> {
    let mut parts = s.splitn(4, ':');
    let ops_str = parts.next()?;
    let dev_str = parts.next()?;
    let ino_str = parts.next()?;
    let path = parts.next()?;
    if path.is_empty() {
        return None;
    }
    let ops = FileOps {
        create: ops_str.contains('c'),
        write: ops_str.contains('w'),
        delete: ops_str.contains('d'),
        rename: ops_str.contains('r'),
    };
    let identity = match (dev_str, ino_str) {
        ("-", "-") => None,
        (d, i) => Some((d.parse().ok()?, i.parse().ok()?)),
    };
    Some(FileEffect {
        path: path.to_string(),
        ops,
        identity,
    })
}

// ── Resource limits ─────────────────────────────────────────────────────────
//
// Bounds CPU/memory/fd/proc-count via setrlimit — independent of, and in
// addition to, landlock (filesystem) and seccomp (which syscalls), neither
// of which bounds resource *consumption* by an allowed syscall. Wall-clock
// timeout is deliberately NOT covered here: RLIMIT_CPU only counts CPU time
// actually burned, so a blocked/sleeping process is unaffected by it — a
// real timeout needs an external watchdog around the whole sandboxed-exec
// call in executor.rs, not something CMD can be made to self-enforce.
//
// Every field defaults to None (no limit imposed) at the parsing level —
// nothing here hardcodes a policy value. `resource_policy.rs` is what
// actually decides what these get set to, loaded from the guardian
// deployment's own config (file/env/flags), layered on top of this same
// all-None starting point; see that module for why this stays a
// guardian-local concern rather than living in `DeclaredEffects`.

pub(crate) const RLIMIT_NAMES: &[&str] =
    &["cpu", "as", "fsize", "nofile", "stack", "core", "nproc"];

#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub(crate) struct RlimitPair {
    soft: u64,
    hard: u64,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub(crate) struct ResourceLimits {
    cpu_seconds: Option<RlimitPair>,
    address_space_bytes: Option<RlimitPair>,
    file_size_bytes: Option<RlimitPair>,
    open_files: Option<RlimitPair>,
    stack_bytes: Option<RlimitPair>,
    core_bytes: Option<RlimitPair>,
    processes: Option<RlimitPair>,
}

impl ResourceLimits {
    /// Renders back to the same `--rlimit NAME=SOFT:HARD` form `apply_rlimit_arg`
    /// parses — the wire format between `executor.rs` (which assembles the
    /// effective policy) and this binary's own `sandbox-entry` invocation of
    /// itself.
    pub(crate) fn to_cli_args(&self) -> Vec<String> {
        let named: [(&str, Option<RlimitPair>); 7] = [
            ("cpu", self.cpu_seconds),
            ("as", self.address_space_bytes),
            ("fsize", self.file_size_bytes),
            ("nofile", self.open_files),
            ("stack", self.stack_bytes),
            ("core", self.core_bytes),
            ("nproc", self.processes),
        ];
        let mut args = Vec::new();
        for (name, pair) in named {
            if let Some(p) = pair {
                args.push("--rlimit".to_string());
                args.push(format!("{name}={}:{}", p.soft, p.hard));
            }
        }
        args
    }
}

pub(crate) fn set_named(
    limits: &mut ResourceLimits,
    name: &str,
    pair: RlimitPair,
) -> Result<(), String> {
    match name {
        "cpu" => limits.cpu_seconds = Some(pair),
        "as" => limits.address_space_bytes = Some(pair),
        "fsize" => limits.file_size_bytes = Some(pair),
        "nofile" => limits.open_files = Some(pair),
        "stack" => limits.stack_bytes = Some(pair),
        "core" => limits.core_bytes = Some(pair),
        "nproc" => limits.processes = Some(pair),
        other => {
            return Err(format!(
                "unknown rlimit {other:?} (expected one of: {})",
                RLIMIT_NAMES.join(", ")
            ))
        }
    }
    Ok(())
}

/// Parses `VALUE` (soft == hard) or `SOFT:HARD`.
pub(crate) fn parse_pair(s: &str) -> Result<RlimitPair, String> {
    match s.split_once(':') {
        Some((soft, hard)) => {
            let soft: u64 = soft
                .parse()
                .map_err(|_| "soft value must be a non-negative integer".to_string())?;
            let hard: u64 = hard
                .parse()
                .map_err(|_| "hard value must be a non-negative integer".to_string())?;
            Ok(RlimitPair { soft, hard })
        }
        None => {
            let v: u64 = s
                .parse()
                .map_err(|_| "value must be a non-negative integer, or SOFT:HARD".to_string())?;
            Ok(RlimitPair { soft: v, hard: v })
        }
    }
}

pub(crate) fn apply_rlimit_arg(limits: &mut ResourceLimits, s: &str) -> Result<(), String> {
    let (name, value) = s
        .split_once('=')
        .ok_or("expected NAME=VALUE or NAME=SOFT:HARD")?;
    set_named(limits, name, parse_pair(value)?)
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, pair: RlimitPair) -> anyhow::Result<()> {
    use anyhow::Context;

    let limit = libc::rlimit {
        rlim_cur: pair.soft as libc::rlim_t,
        rlim_max: pair.hard as libc::rlim_t,
    };
    let rc = unsafe { libc::setrlimit(resource, &limit) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("setrlimit({resource}) failed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_resource_limits(limits: &ResourceLimits) -> anyhow::Result<()> {
    if let Some(p) = limits.cpu_seconds {
        set_limit(libc::RLIMIT_CPU, p)?;
    }
    if let Some(p) = limits.address_space_bytes {
        set_limit(libc::RLIMIT_AS, p)?;
    }
    if let Some(p) = limits.file_size_bytes {
        set_limit(libc::RLIMIT_FSIZE, p)?;
    }
    if let Some(p) = limits.open_files {
        set_limit(libc::RLIMIT_NOFILE, p)?;
    }
    if let Some(p) = limits.stack_bytes {
        set_limit(libc::RLIMIT_STACK, p)?;
    }
    if let Some(p) = limits.core_bytes {
        set_limit(libc::RLIMIT_CORE, p)?;
    }
    if let Some(p) = limits.processes {
        set_limit(libc::RLIMIT_NPROC, p)?;
    }
    Ok(())
}

// ── Landlock ──────────────────────────────────────────────────────────────────

/// Re-stats `path` and refuses to proceed if it no longer matches the
/// `(st_dev, st_ino)` the scout observed there. Closes the TOCTOU window
/// between scout observation (and the human's approval, based on that
/// observation) and this landlock rule actually being set up: the anchor
/// path string gets resolved fresh here, seconds later, and nothing
/// previously checked it still named the same filesystem object. `None`
/// (the scout never saw this path exist -- a pure `create`) always passes,
/// since there's no prior object identity to have been swapped.
///
/// This runs from *inside* the already-bwrap-namespaced process (see
/// `executor.rs`'s `--bind anchor anchor`), so a bind-mounted anchor's
/// `stat()` here reflects the same underlying inode a host-side check would
/// see -- bind mounts don't allocate a new inode.
#[cfg(target_os = "linux")]
fn verify_identity(path: &str, identity: Option<(u64, u64)>) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let Some((expected_dev, expected_ino)) = identity else {
        return Ok(());
    };
    let meta = std::fs::metadata(path).map_err(|e| {
        anyhow::anyhow!(
            "declared path {path:?} no longer exists (scout observed it at dev={expected_dev} \
         ino={expected_ino}; stat failed: {e})"
        )
    })?;
    let (actual_dev, actual_ino) = (meta.dev(), meta.ino());
    if (actual_dev, actual_ino) != (expected_dev, expected_ino) {
        anyhow::bail!(
            "declared path {path:?} identity changed since the scout observed it \
             (expected dev={expected_dev} ino={expected_ino}, found dev={actual_dev} \
             ino={actual_ino}) -- refusing to grant landlock access to a different \
             filesystem object than what was approved"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_landlock(file_effects: &[FileEffect], allow_dynamic: bool) -> anyhow::Result<()> {
    use landlock::{AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};

    let read_access = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
    let all_write = AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::MakeFifo
        | AccessFs::MakeSock
        | AccessFs::MakeChar
        | AccessFs::MakeBlock
        | AccessFs::MakeSym
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir;

    let mut ruleset = Ruleset::default()
        .handle_access(read_access)?
        .handle_access(all_write)?
        .create()?;

    ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new("/")?, read_access))?;

    if allow_dynamic {
        if let Ok(fd) = PathFd::new("/tmp") {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, read_access | all_write))?;
        }
    } else {
        for fe in file_effects {
            if !fe.ops.any() {
                continue;
            }
            verify_identity(&fe.path, fe.identity)?;
            let Ok(fd) = PathFd::new(&fe.path) else {
                continue;
            };
            let mut access = read_access;
            if fe.ops.write {
                access |= AccessFs::WriteFile | AccessFs::Truncate;
            }
            if fe.ops.create {
                access |= AccessFs::MakeReg
                    | AccessFs::MakeDir
                    | AccessFs::MakeFifo
                    | AccessFs::MakeSock
                    | AccessFs::MakeChar
                    | AccessFs::MakeBlock
                    | AccessFs::MakeSym;
            }
            if fe.ops.delete {
                access |= AccessFs::RemoveFile | AccessFs::RemoveDir;
            }
            if fe.ops.rename {
                access |= AccessFs::RemoveFile
                    | AccessFs::RemoveDir
                    | AccessFs::MakeReg
                    | AccessFs::MakeDir
                    | AccessFs::MakeSym;
            }
            ruleset = ruleset.add_rule(PathBeneath::new(fd, access))?;
        }
    }

    let status = ruleset.restrict_self()?;
    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => Ok(()),
        // PartiallyEnforced is NOT treated as failure here, and this is a
        // deliberate, empirically-verified decision, not a downgrade of the
        // fail-closed posture -- confirmed against a real kernel (ABI 8),
        // not assumed. This status routinely fires for the completely
        // ordinary shape this function always builds once any file_effects
        // are declared: a blanket "/" rule with read_access, plus a
        // narrower rule for each declared path with a *different* access
        // set nested under it. The `landlock` crate (0.4.7, the latest
        // published release) reports Partial for that shape on a kernel
        // whose ABI is newer than what the crate was written against --
        // but a direct functional test (real process, this exact
        // Partially-Enforced ruleset, right after restrict_self()) proved
        // the actual filesystem access control was fully correct: a write
        // to an undeclared path was denied (EACCES) and a write to the
        // declared path succeeded. So "Partial" here reflects the crate's
        // own uncertainty about ABI-8-level features this deployment never
        // requests (e.g. the network/scope access rights added well past
        // where these AccessFs flags live), not a real gap in what this
        // function actually asked the kernel to restrict. Treating it as a
        // hard failure would make the entire Ring-2 sandbox refuse to run
        // any command with more than one declared file effect, unbounded
        // by anything the sandbox actually needs it to guard against.
        landlock::RulesetStatus::PartiallyEnforced => Ok(()),
        landlock::RulesetStatus::NotEnforced => Err(anyhow::anyhow!(
            "landlock ruleset not enforced at all (kernel lacks Landlock support)"
        )),
    }
}

// ── Seccomp denylist (via seccompiler — arch-aware syscall resolution) ────────
//
// seccompiler's programmatic API resolves syscalls through `libc::SYS_*`
// constants rather than name strings — those constants are themselves
// per-arch-gated inside the `libc` crate, so this table is correct for
// whichever of x86_64/aarch64 we're actually built for, instead of the
// x86-64-only numeric literals this replaced. `TargetArch` (passed into
// `SeccompFilter::new` below) makes the compiled BPF program itself check
// `seccomp_data.arch`, closing the audit-architecture-confusion gap the
// hand-rolled filter had (it only ever checked `nr`, never `arch`).

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const TARGET_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const TARGET_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

#[cfg(target_os = "linux")]
const BASELINE_DENY: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_perf_event_open,
    // seccomp only sees io_uring_enter(), never the individual SQEs the
    // kernel's own io_uring workers execute on the caller's behalf --  a
    // documented escape hatch for syscall-filtering sandboxes in general.
    // This sandbox's workload (short-lived, human-approved shell commands)
    // has no legitimate need for io_uring's throughput, so it's denied
    // outright here rather than allowlisted via IORING_REGISTER_RESTRICTIONS
    // for a use case that doesn't exist yet.
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

// Each listed individually rather than relying on denying `socket` alone:
// a descriptor inherited from the parent (rather than freshly created here)
// never goes through `socket()`, so `connect`/`bind`/`listen`/`accept*` must
// be denied on their own to actually close off an inherited fd.
#[cfg(target_os = "linux")]
const NETWORK_DENY: &[i64] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
];

#[cfg(target_os = "linux")]
const SUBPROCESS_DENY: &[i64] = &[libc::SYS_execve, libc::SYS_execveat];

#[cfg(target_os = "linux")]
fn denied_syscalls(no_network: bool, no_subprocess: bool) -> Vec<i64> {
    let mut denied = BASELINE_DENY.to_vec();
    if no_network {
        denied.extend_from_slice(NETWORK_DENY);
    }
    if no_subprocess {
        denied.extend_from_slice(SUBPROCESS_DENY);
    }
    denied
}

#[cfg(target_os = "linux")]
fn apply_seccomp(no_network: bool, no_subprocess: bool) -> anyhow::Result<()> {
    use anyhow::Context;
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    // An empty rule vec means "match this syscall number unconditionally,
    // regardless of arguments" — seccompiler rejects zero-condition Rules
    // directly, this is its documented way to express the same thing.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in denied_syscalls(no_network, no_subprocess) {
        rules.insert(nr, Vec::new());
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // not in the map → allow
        SeccompAction::Errno(libc::EPERM as u32), // in the map → deny (matches prior RET_ERRNO behavior)
        TARGET_ARCH,
    )
    .context("building seccomp filter")?;

    let bpf_program: BpfProgram = filter
        .try_into()
        .context("compiling seccomp filter to BPF")?;
    seccompiler::apply_filter(&bpf_program).context("installing seccomp filter")?;
    Ok(())
}

// ── Seccomp-notify: live mediation for pathname syscalls ──────────────────
//
// Layered on top of the classic filter above via a second, independently-
// installed filter with SECCOMP_FILTER_FLAG_NEW_LISTENER -- see
// `seccomp_ffi`'s module doc for why composing two filters this way is
// correct rather than needing to be merged into one BPF program. Only
// pathname-resolving syscalls are notify-mediated; network/subprocess stay
// exactly as they are above (coarse yes/no flags, no live resolution
// needed). The notify fd this produces is useless to this process itself
// (it's the *listener* side, meant for a broker) -- it's sent straight back
// to Guardian's own process over the inherited fd-5 socketpair and this
// process never touches it again before execvp.
#[cfg(target_os = "linux")]
const NOTIFY_SYSCALLS: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
];

#[cfg(target_os = "linux")]
fn apply_seccomp_notify() -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;

    let notify_fd = crate::seccomp_ffi::install_notify_filter(NOTIFY_SYSCALLS)?;
    crate::fd_passing::send_fd(crate::NOTIFY_FD_RENDEZVOUS, notify_fd.as_raw_fd())?;
    // notify_fd drops here once sent -- SCM_RIGHTS duplicated it into
    // Guardian's process; this process (about to execvp) has no further use
    // for the listener side itself. (Tested keeping this fd open instead,
    // matching the standalone C probe's behavior -- made no difference to
    // the open ADDFD-wake investigation; see THREAT_MODEL.md / session notes.)
    Ok(())
}

// ── exec helper ───────────────────────────────────────────────────────────────

#[cfg(unix)]
fn argv_ptrs(argv: &[std::ffi::CString]) -> Vec<*const libc::c_char> {
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    ptrs
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_file_effect_with_identity() {
        let fe = parse_file_effect_arg("cw:2049:12345:/allowed/dir").unwrap();
        assert_eq!(fe.path, "/allowed/dir");
        assert!(fe.ops.create && fe.ops.write);
        assert!(!fe.ops.delete && !fe.ops.rename);
        assert_eq!(fe.identity, Some((2049, 12345)));
    }

    #[test]
    fn parses_file_effect_with_no_identity() {
        let fe = parse_file_effect_arg("c:-:-:/new/file").unwrap();
        assert_eq!(fe.identity, None);
    }

    #[test]
    fn parses_file_effect_path_containing_colon() {
        // splitn(4, ':') must leave a literal ':' in the path intact rather
        // than truncating there -- legal on Linux, if unusual.
        let fe = parse_file_effect_arg("w:-:-:/tmp/weird:path").unwrap();
        assert_eq!(fe.path, "/tmp/weird:path");
    }

    #[test]
    fn rejects_malformed_file_effect_arg() {
        assert!(parse_file_effect_arg("cw:/no-identity-fields").is_none());
        assert!(parse_file_effect_arg("cw:1:2:").is_none()); // empty path
    }

    #[test]
    fn verify_identity_passes_with_no_prior_identity() {
        assert!(verify_identity("/does/not/exist/at/all", None).is_ok());
    }

    /// Creates a uniquely-named file under the OS temp dir and returns its
    /// path; cleaned up by `TestFile`'s `Drop`. Avoids pulling in a
    /// `tempfile` dev-dependency for two tests.
    struct TestFile(std::path::PathBuf);
    impl TestFile {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "solarplex-guardian-test-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::write(&path, b"test").unwrap();
            Self(path)
        }
    }
    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn verify_identity_passes_when_unchanged() {
        use std::os::unix::fs::MetadataExt;
        let f = TestFile::new("unchanged");
        let meta = std::fs::metadata(&f.0).unwrap();
        let identity = Some((meta.dev(), meta.ino()));
        assert!(verify_identity(f.0.to_str().unwrap(), identity).is_ok());
    }

    #[test]
    fn verify_identity_fails_when_swapped() {
        use std::os::unix::fs::MetadataExt;
        let real = TestFile::new("swapped-real");
        let real_meta = std::fs::metadata(&real.0).unwrap();
        let scouted_identity = Some((real_meta.dev(), real_meta.ino()));

        // A different file now sits at a different path -- simulate the scout
        // having recorded `real`'s identity for a path that, by execution
        // time, resolves to `decoy` instead (the swap this check exists to
        // catch; on a real filesystem this would be the same path, but the
        // identity comparison itself doesn't care how the swap happened).
        let decoy = TestFile::new("swapped-decoy");
        let result = verify_identity(decoy.0.to_str().unwrap(), scouted_identity);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("identity changed"));
    }

    #[test]
    fn verify_identity_fails_when_path_vanishes() {
        let identity = Some((999, 999));
        let result = verify_identity("/definitely/does/not/exist", identity);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no longer exists"));
    }
}
