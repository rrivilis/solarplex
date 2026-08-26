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

#[cfg(target_os = "linux")]
async fn run_scout_linux(command: &str, timeout_secs: u64) -> ScoutManifest {
    use std::time::Instant;
    use tokio::process::Command;

    let avail = Command::new("strace").arg("--version").output().await;
    if avail.is_err() {
        return ScoutManifest {
            command: command.to_string(),
            sandbox_backend: "none".to_string(),
            ..Default::default()
        };
    }

    let tmp = format!("/tmp/solarplex_scout_{}.log", ulid::Ulid::new());
    let t0 = Instant::now();

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        Command::new("strace")
            .args([
                "-f",
                "-s",
                "256",
                "-e",
                "trace=openat,unlinkat,unlink,renameat,rename,connect,execve",
                "-o",
                &tmp,
                "--",
                "sh",
                "-c",
                command,
            ])
            .output(),
    )
    .await
    .is_err();

    let duration_ms = t0.elapsed().as_millis() as u64;
    let log = tokio::fs::read_to_string(&tmp).await.unwrap_or_default();
    let _ = tokio::fs::remove_file(&tmp).await;

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
        sandbox_backend: "strace".to_string(),
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
    if is_failed_syscall(s) {
        return None;
    }
    let (_, path) = quoted_string(s).ok()?;
    if path.is_empty() {
        return None;
    }
    let ops = FileOps {
        create: s.contains("O_CREAT"),
        write: s.contains("O_WRONLY") || s.contains("O_RDWR") || s.contains("O_TRUNC"),
        delete: false,
        rename: false,
    };
    Some((path, ops))
}

fn parse_unlink(s: &str) -> Option<String> {
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

fn parse_rename(s: &str) -> Option<(String, String)> {
    if is_failed_syscall(s) {
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
    if is_failed_syscall(s) {
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
