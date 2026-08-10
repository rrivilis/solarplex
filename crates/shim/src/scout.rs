//! Runahead scout for the shim — identical to the sidecar's scout.rs
//! but referencing the shim's own SessionClient.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, Mutex};

use protocol::effects::{ExecutionManifest, ScoutManifest};
#[cfg(target_os = "linux")]
use protocol::effects::{FileEvent, FileOps};

#[cfg(target_os = "linux")]
const MAX_EVENTS: usize = 1_000;

#[cfg(target_os = "linux")]
const NOISE_PREFIXES: &[&str] = &[
    "/proc/", "/sys/", "/dev/",
    "/usr/lib/", "/usr/lib64/", "/usr/share/",
    "/lib/", "/lib64/",
    "/etc/ld.so", "/etc/nsswitch.conf",
    "/etc/passwd", "/etc/group", "/etc/localtime",
];

pub fn extract_command(args: &serde_json::Value) -> Option<String> {
    for field in &["command", "cmd", "shell", "script", "run"] {
        if let Some(s) = args.get(field).and_then(|v| v.as_str()) {
            let s = s.trim();
            if !s.is_empty() { return Some(s.to_string()); }
        }
    }
    None
}

pub async fn run_scout(command: &str, timeout_secs: u64) -> ScoutManifest {
    #[cfg(target_os = "linux")]
    { run_scout_linux(command, timeout_secs).await }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = timeout_secs;
        ScoutManifest { command: command.to_string(), sandbox_backend: "none".to_string(), ..Default::default() }
    }
}

pub fn build_execution_manifest(
    pre:   &HashMap<String, (i64, u64)>,
    post:  &HashMap<String, (i64, u64)>,
    scout: Option<&ScoutManifest>,
) -> ExecutionManifest {
    let scout_writes: Vec<String> = scout
        .map(|m| m.file_effects.iter().map(|fe| fe.path.clone()).collect())
        .unwrap_or_default();

    let mut files_changed     = Vec::new();
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

    let missing_writes: Vec<String> = scout_writes.iter()
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

    ExecutionManifest { files_changed, missing_writes, unexpected_writes }
}

// ── Linux strace backend ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_scout_linux(command: &str, timeout_secs: u64) -> ScoutManifest {
    use std::time::Instant;
    use tokio::process::Command;

    let avail = Command::new("strace").arg("--version").output().await;
    if avail.is_err() {
        return ScoutManifest { command: command.to_string(), sandbox_backend: "none".to_string(), ..Default::default() };
    }

    let tmp = format!("/tmp/solarplex_scout_{}.log", ulid::Ulid::new());
    let t0  = Instant::now();

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        Command::new("strace")
            .args(["-f", "-s", "256", "-e",
                "trace=openat,unlinkat,unlink,renameat,rename,connect,execve",
                "-o", &tmp, "--", "sh", "-c", command])
            .output(),
    ).await.is_err();

    let duration_ms = t0.elapsed().as_millis() as u64;
    let log = tokio::fs::read_to_string(&tmp).await.unwrap_or_default();
    let _   = tokio::fs::remove_file(&tmp).await;

    let (mut reads, file_events, mut connects, mut execs) = parse_strace_output(&log);
    reads.sort_unstable(); reads.dedup();
    connects.sort_unstable(); connects.dedup();
    execs.sort_unstable(); execs.dedup();

    let mut effect_map: HashMap<String, FileOps> = HashMap::new();
    for fe in file_events {
        effect_map.entry(fe.path).or_default().merge(&fe.ops);
    }
    let mut file_effects: Vec<FileEvent> = effect_map.into_iter()
        .map(|(path, ops)| FileEvent { path, ops }).collect();
    file_effects.sort_by(|a, b| a.path.cmp(&b.path));

    let total     = reads.len() + file_effects.len() + connects.len() + execs.len();
    let truncated = timed_out || total >= MAX_EVENTS;

    ScoutManifest {
        command: command.to_string(),
        file_reads: reads, file_effects,
        network_connects: connects, subprocesses: execs,
        duration_ms, sandbox_backend: "strace".to_string(), truncated,
    }
}

#[cfg(target_os = "linux")]
fn parse_strace_output(content: &str) -> (Vec<String>, Vec<FileEvent>, Vec<String>, Vec<String>) {
    let mut reads = Vec::new(); let mut effects = Vec::new();
    let mut connects = Vec::new(); let mut execs = Vec::new();
    let mut count = 0usize;

    for line in content.lines() {
        if count >= MAX_EVENTS { break; }
        let call = strip_pid_prefix(line);
        if call.starts_with("openat(") {
            if let Some((path, ops)) = parse_openat(call) {
                if !is_noise(&path) {
                    if ops.any() { effects.push(FileEvent { path, ops }); }
                    else { reads.push(path); }
                    count += 1;
                }
            }
        } else if call.starts_with("unlinkat(") || call.starts_with("unlink(") {
            if let Some(path) = parse_unlink(call) {
                if !is_noise(&path) {
                    effects.push(FileEvent { path, ops: FileOps { delete: true, ..Default::default() } });
                    count += 1;
                }
            }
        } else if call.starts_with("renameat(") || call.starts_with("rename(") {
            if let Some((src, dst)) = parse_rename(call) {
                if !is_noise(&src) {
                    effects.push(FileEvent { path: src, ops: FileOps { rename: true, delete: true, ..Default::default() } });
                    count += 1;
                }
                if !is_noise(&dst) {
                    effects.push(FileEvent { path: dst, ops: FileOps { rename: true, create: true, ..Default::default() } });
                    count += 1;
                }
            }
        } else if call.starts_with("connect(") {
            if let Some(addr) = parse_connect(call) { connects.push(addr); count += 1; }
        } else if call.starts_with("execve(") {
            if let Some(exe) = parse_execve(call) {
                if !is_noise(&exe) { execs.push(exe); count += 1; }
            }
        }
    }
    (reads, effects, connects, execs)
}

#[cfg(target_os = "linux")]
fn is_noise(path: &str) -> bool { NOISE_PREFIXES.iter().any(|p| path.starts_with(p)) }

#[cfg(target_os = "linux")]
fn strip_pid_prefix(line: &str) -> &str {
    let line = line.trim_start();
    if line.starts_with('[') {
        if let Some(b) = line.find(']') { return line[b + 1..].trim_start(); }
    }
    line.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ')
}

#[cfg(target_os = "linux")]
fn parse_openat(s: &str) -> Option<(String, FileOps)> {
    if is_failed_syscall(s) { return None; }
    let q1 = s.find('"')? + 1;
    let q2 = s[q1..].find('"')? + q1;
    let path = s[q1..q2].to_string();
    if path.is_empty() { return None; }
    let ops = FileOps {
        create: s.contains("O_CREAT"),
        write:  s.contains("O_WRONLY") || s.contains("O_RDWR") || s.contains("O_TRUNC"),
        delete: false, rename: false,
    };
    Some((path, ops))
}

#[cfg(target_os = "linux")]
fn parse_unlink(s: &str) -> Option<String> {
    if is_failed_syscall(s) { return None; }
    let q1 = s.find('"')? + 1;
    let q2 = s[q1..].find('"')? + q1;
    let path = s[q1..q2].to_string();
    if path.is_empty() { None } else { Some(path) }
}

#[cfg(target_os = "linux")]
fn parse_rename(s: &str) -> Option<(String, String)> {
    if is_failed_syscall(s) { return None; }
    let q1 = s.find('"')? + 1; let q2 = s[q1..].find('"')? + q1;
    let src = s[q1..q2].to_string();
    let q3 = s[q2 + 1..].find('"')? + q2 + 2; let q4 = s[q3..].find('"')? + q3;
    let dst = s[q3..q4].to_string();
    if src.is_empty() || dst.is_empty() { None } else { Some((src, dst)) }
}

#[cfg(target_os = "linux")]
fn parse_connect(s: &str) -> Option<String> {
    if is_failed_syscall(s) { return None; }
    if s.contains("AF_UNIX") || s.contains("AF_NETLINK") { return None; }
    let marker = "sin_addr=inet_addr(\"";
    let start  = s.find(marker)? + marker.len();
    let end    = s[start..].find('"')? + start;
    let ip     = s[start..end].to_string();
    let pm     = "sin_port=htons(";
    let ps     = s.find(pm)? + pm.len();
    let pe     = s[ps..].find(')')? + ps;
    Some(format!("{ip}:{}", &s[ps..pe]))
}

#[cfg(target_os = "linux")]
fn parse_execve(s: &str) -> Option<String> {
    if is_failed_syscall(s) { return None; }
    let q1 = s.find('"')? + 1; let q2 = s[q1..].find('"')? + q1;
    let path = s[q1..q2].to_string();
    if path.is_empty() { None } else { Some(path) }
}

#[cfg(target_os = "linux")]
fn is_failed_syscall(s: &str) -> bool {
    s.rfind(" = ").map(|i| s[i + 3..].trim().starts_with('-')).unwrap_or(false)
}

// ── Bounded issue pool ────────────────────────────────────────────────────────

pub struct ScoutJob {
    pub command:     String,
    pub approval_id: String,
    pub session:     Arc<crate::session::SessionClient>,
    pub result_tx:   oneshot::Sender<ScoutManifest>,
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
    pub categories:    HashMap<String, CategoryConfig>,
    pub timeout_secs:  u64,
}

impl Default for ScoutPoolConfig {
    fn default() -> Self {
        Self { default_width: 4, default_queue: 64, categories: HashMap::new(), timeout_secs: 20 }
    }
}

#[derive(Clone)]
struct SubPool { tx: mpsc::Sender<ScoutJob> }

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
                    job.session.patch_approval_scout(&job.approval_id, &manifest).await;
                    let declared = protocol::effects::DeclaredEffects::from_scout(&manifest);
                    job.session.patch_approval_declared_effects(&job.approval_id, &declared).await;
                    let _ = job.result_tx.send(manifest);
                }
            });
        }
        Self { tx }
    }

    fn try_send(&self, job: ScoutJob) -> bool { self.tx.try_send(job).is_ok() }
}

#[derive(Clone)]
pub struct ScoutPool {
    default: SubPool,
    named:   HashMap<String, SubPool>,
}

impl ScoutPool {
    pub fn spawn(cfg: &ScoutPoolConfig) -> Self {
        let default = SubPool::spawn(cfg.default_width, cfg.default_queue, cfg.timeout_secs);
        let named   = cfg.categories.iter()
            .map(|(name, cat)| (name.clone(), SubPool::spawn(cat.width, cat.queue, cfg.timeout_secs)))
            .collect();
        Self { default, named }
    }

    pub fn try_dispatch(
        &self,
        command:     String,
        approval_id: String,
        session:     Arc<crate::session::SessionClient>,
        category:    Option<&str>,
    ) -> Option<oneshot::Receiver<ScoutManifest>> {
        let (result_tx, result_rx) = oneshot::channel();
        let job = ScoutJob { command, approval_id, session, result_tx };
        let pool = category.and_then(|c| self.named.get(c)).unwrap_or(&self.default);
        if pool.try_send(job) { Some(result_rx) } else { None }
    }
}
