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
        let argv: Vec<std::ffi::CString> = match opts.command.iter()
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
    ops:  FileOps,
}

#[derive(Default)]
#[allow(dead_code)]
struct FileOps {
    create: bool,
    write:  bool,
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
    no_network:      bool,
    no_subprocess:   bool,
    file_effects:    Vec<FileEffect>,
    allow_dynamic:   bool,
    resource_limits: ResourceLimits,
    command:         Vec<String>,
}

fn parse_args(args: &[String]) -> Result<SandboxOpts, String> {
    let mut no_network      = false;
    let mut no_subprocess   = false;
    let mut file_effects    = Vec::new();
    let mut allow_dynamic   = false;
    let mut resource_limits = ResourceLimits::default();
    let mut command         = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-network"    => { no_network    = true; i += 1; }
            "--no-subprocess" => { no_subprocess = true; i += 1; }
            "--allow-dynamic" => { allow_dynamic = true; i += 1; }
            "--file-effect" => {
                i += 1;
                let val = args.get(i).ok_or("--file-effect requires a value")?;
                let fe  = parse_file_effect_arg(val)
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
    Ok(SandboxOpts { no_network, no_subprocess, file_effects, allow_dynamic, resource_limits, command })
}

fn parse_file_effect_arg(s: &str) -> Option<FileEffect> {
    let (ops_str, path) = s.split_once(':')?;
    if path.is_empty() { return None; }
    let ops = FileOps {
        create: ops_str.contains('c'),
        write:  ops_str.contains('w'),
        delete: ops_str.contains('d'),
        rename: ops_str.contains('r'),
    };
    Some(FileEffect { path: path.to_string(), ops })
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

pub(crate) const RLIMIT_NAMES: &[&str] = &["cpu", "as", "fsize", "nofile", "stack", "core", "nproc"];

#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub(crate) struct RlimitPair {
    soft: u64,
    hard: u64,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub(crate) struct ResourceLimits {
    cpu_seconds:         Option<RlimitPair>,
    address_space_bytes: Option<RlimitPair>,
    file_size_bytes:     Option<RlimitPair>,
    open_files:          Option<RlimitPair>,
    stack_bytes:         Option<RlimitPair>,
    core_bytes:          Option<RlimitPair>,
    processes:           Option<RlimitPair>,
}

impl ResourceLimits {
    /// Renders back to the same `--rlimit NAME=SOFT:HARD` form `apply_rlimit_arg`
    /// parses — the wire format between `executor.rs` (which assembles the
    /// effective policy) and this binary's own `sandbox-entry` invocation of
    /// itself.
    pub(crate) fn to_cli_args(&self) -> Vec<String> {
        let named: [(&str, Option<RlimitPair>); 7] = [
            ("cpu",    self.cpu_seconds),
            ("as",     self.address_space_bytes),
            ("fsize",  self.file_size_bytes),
            ("nofile", self.open_files),
            ("stack",  self.stack_bytes),
            ("core",   self.core_bytes),
            ("nproc",  self.processes),
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

pub(crate) fn set_named(limits: &mut ResourceLimits, name: &str, pair: RlimitPair) -> Result<(), String> {
    match name {
        "cpu"    => limits.cpu_seconds         = Some(pair),
        "as"     => limits.address_space_bytes = Some(pair),
        "fsize"  => limits.file_size_bytes     = Some(pair),
        "nofile" => limits.open_files          = Some(pair),
        "stack"  => limits.stack_bytes         = Some(pair),
        "core"   => limits.core_bytes          = Some(pair),
        "nproc"  => limits.processes           = Some(pair),
        other => return Err(format!(
            "unknown rlimit {other:?} (expected one of: {})", RLIMIT_NAMES.join(", ")
        )),
    }
    Ok(())
}

/// Parses `VALUE` (soft == hard) or `SOFT:HARD`.
pub(crate) fn parse_pair(s: &str) -> Result<RlimitPair, String> {
    match s.split_once(':') {
        Some((soft, hard)) => {
            let soft: u64 = soft.parse().map_err(|_| "soft value must be a non-negative integer".to_string())?;
            let hard: u64 = hard.parse().map_err(|_| "hard value must be a non-negative integer".to_string())?;
            Ok(RlimitPair { soft, hard })
        }
        None => {
            let v: u64 = s.parse().map_err(|_| "value must be a non-negative integer, or SOFT:HARD".to_string())?;
            Ok(RlimitPair { soft: v, hard: v })
        }
    }
}

pub(crate) fn apply_rlimit_arg(limits: &mut ResourceLimits, s: &str) -> Result<(), String> {
    let (name, value) = s.split_once('=').ok_or("expected NAME=VALUE or NAME=SOFT:HARD")?;
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
    if let Some(p) = limits.cpu_seconds         { set_limit(libc::RLIMIT_CPU,    p)?; }
    if let Some(p) = limits.address_space_bytes { set_limit(libc::RLIMIT_AS,     p)?; }
    if let Some(p) = limits.file_size_bytes     { set_limit(libc::RLIMIT_FSIZE,  p)?; }
    if let Some(p) = limits.open_files          { set_limit(libc::RLIMIT_NOFILE, p)?; }
    if let Some(p) = limits.stack_bytes         { set_limit(libc::RLIMIT_STACK,  p)?; }
    if let Some(p) = limits.core_bytes          { set_limit(libc::RLIMIT_CORE,   p)?; }
    if let Some(p) = limits.processes           { set_limit(libc::RLIMIT_NPROC,  p)?; }
    Ok(())
}

// ── Landlock ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn apply_landlock(file_effects: &[FileEffect], allow_dynamic: bool) -> anyhow::Result<()> {
    use landlock::{AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};

    let read_access = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
    let all_write   = AccessFs::WriteFile | AccessFs::Truncate
        | AccessFs::MakeReg  | AccessFs::MakeDir
        | AccessFs::MakeFifo | AccessFs::MakeSock
        | AccessFs::MakeChar | AccessFs::MakeBlock | AccessFs::MakeSym
        | AccessFs::RemoveFile | AccessFs::RemoveDir;

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
            if !fe.ops.any() { continue; }
            let Ok(fd) = PathFd::new(&fe.path) else { continue };
            let mut access = read_access;
            if fe.ops.write  { access |= AccessFs::WriteFile | AccessFs::Truncate; }
            if fe.ops.create {
                access |= AccessFs::MakeReg  | AccessFs::MakeDir
                    | AccessFs::MakeFifo | AccessFs::MakeSock
                    | AccessFs::MakeChar | AccessFs::MakeBlock | AccessFs::MakeSym;
            }
            if fe.ops.delete { access |= AccessFs::RemoveFile | AccessFs::RemoveDir; }
            if fe.ops.rename {
                access |= AccessFs::RemoveFile | AccessFs::RemoveDir
                    | AccessFs::MakeReg | AccessFs::MakeDir | AccessFs::MakeSym;
            }
            ruleset = ruleset.add_rule(PathBeneath::new(fd, access))?;
        }
    }

    let status = ruleset.restrict_self()?;
    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => Ok(()),
        landlock::RulesetStatus::PartiallyEnforced => Err(anyhow::anyhow!(
            "landlock ruleset only partially enforced (kernel supports some but not all \
             requested Landlock ABI features)"
        )),
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
    if no_network { denied.extend_from_slice(NETWORK_DENY); }
    if no_subprocess { denied.extend_from_slice(SUBPROCESS_DENY); }
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
        SeccompAction::Allow,                      // not in the map → allow
        SeccompAction::Errno(libc::EPERM as u32),   // in the map → deny (matches prior RET_ERRNO behavior)
        TARGET_ARCH,
    )
    .context("building seccomp filter")?;

    let bpf_program: BpfProgram = filter.try_into().context("compiling seccomp filter to BPF")?;
    seccompiler::apply_filter(&bpf_program).context("installing seccomp filter")?;
    Ok(())
}

// ── exec helper ───────────────────────────────────────────────────────────────

#[cfg(unix)]
fn argv_ptrs(argv: &[std::ffi::CString]) -> Vec<*const libc::c_char> {
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    ptrs
}
