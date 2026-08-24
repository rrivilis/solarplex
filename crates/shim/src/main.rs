mod approval;
mod policy;
mod scout;
mod sealed;
mod session;

use std::collections::HashMap;
use std::sync::Arc;

use protocol::ipc;
use tokio::sync::mpsc;

use sealed::SealedJson;
use session::SessionClient;

// Well-known fd numbers placed in each child by dup2 in the pre_exec hook.
// These are part of the IPC API surface — changing them requires matching
// updates in sidecar/src/main.rs and guardian/src/main.rs.
const ADAPTER_IPC_FD:  i32 = 3; // adapter reads/writes its shim socket on this fd
const GUARDIAN_IPC_FD: i32 = 4; // guardian reads/writes its shim socket on this fd

/// This shim's own held cap-node: `(session_id, actor_id, cap_id,
/// permissions)` — set once via the `SOLARPLEX_TOKEN` exchange at startup
/// and never mutated after. See `crate::sealed`'s module doc for why this
/// specific tuple is sealed rather than plain `Config` fields: it's the
/// closest thing to a single cap-DAG node held in any process's memory in
/// this codebase (the DAG itself is server-side — docs/threat-model.md
/// §4.3), and `permissions` is the shim's own local, first-line
/// enforcement of the DAG's attenuation invariant (`approval::handle_proposal`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub session_id:  String,
    pub actor_id:    String,
    pub cap_id:      Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone)]
pub struct Config {
    /// Private: reachable only via `Config::identity()`, which always
    /// deserializes fresh from the sealed region rather than exposing a
    /// long-lived reference to a plain field — see `crate::sealed`.
    identity:             SealedJson<Identity>,
    pub server_ws:        String,
    pub listen_port:      u16,
    pub upstream_mcp:     String,
    pub upstream_mcp_cmd: Option<String>,
    pub fail_open:        bool,
    pub tool_categories:  HashMap<String, String>,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let permissions: Vec<String> = std::env::var("SOLARPLEX_PERMISSIONS")
            .ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let tool_categories: HashMap<String, String> = std::env::var("SOLARPLEX_TOOL_CATEGORIES")
            .ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let identity = Identity {
            session_id:  std::env::var("SOLARPLEX_SESSION_ID")?,
            actor_id:    std::env::var("SOLARPLEX_ACTOR_ID")?,
            cap_id:      std::env::var("SOLARPLEX_CAP_ID").ok(),
            permissions,
        };
        Ok(Self {
            identity:     SealedJson::new(&identity),
            server_ws:    std::env::var("SOLARPLEX_WS").unwrap_or_else(|_| "ws://localhost:8080".into()),
            listen_port:  std::env::var("SIDECAR_PORT").unwrap_or_else(|_| "7777".into()).parse()?,
            upstream_mcp: std::env::var("UPSTREAM_MCP_URL").unwrap_or_default(),
            upstream_mcp_cmd: std::env::var("UPSTREAM_MCP_CMD").ok(),
            fail_open:    std::env::var("FAIL_OPEN").map(|v| v == "true" || v == "1").unwrap_or(false),
            tool_categories,
        })
    }

    /// Fresh, owned snapshot of this shim's held cap-node identity —
    /// deserialized from the sealed region on every call (see
    /// `crate::sealed`'s module doc). Cheap: a handful of small
    /// string/Vec fields, called far less often than once per proposal.
    pub fn identity(&self) -> Identity {
        self.identity.get()
    }
}

/// Handle to the guardian IPC socket shared across approval tasks.
///
/// The guardian processes exec requests sequentially (bwrap is synchronous),
/// so serialising all sends through a Mutex is correct and adds no latency
/// penalty.  The Arc allows cheap cloning across spawned tokio tasks.
#[derive(Clone)]
pub struct GuardianHandle {
    pub socket: Arc<tokio::sync::Mutex<tokio::net::UnixStream>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "solarplex_shim=info".into()),
        )
        .init();

    // Token exchange.
    if let Ok(token) = std::env::var("SOLARPLEX_TOKEN") {
        let server_http = std::env::var("SOLARPLEX_WS")
            .unwrap_or_else(|_| "ws://localhost:8080".into())
            .replace("ws://", "http://").replace("wss://", "https://");
        tracing::info!("shim: exchanging attach token…");
        let resp = reqwest::Client::new()
            .post(format!("{server_http}/api/attach"))
            .json(&serde_json::json!({ "token": token }))
            .send().await
            .map_err(|e| anyhow::anyhow!("token exchange failed: {e}"))?;
        if resp.status() == reqwest::StatusCode::GONE {
            anyhow::bail!("attach token is expired or invalid");
        }
        if !resp.status().is_success() {
            anyhow::bail!("token exchange failed: HTTP {}", resp.status());
        }
        let body: serde_json::Value = resp.json().await?;
        let session_id = body["session_id"].as_str()
            .ok_or_else(|| anyhow::anyhow!("token exchange: missing session_id"))?.to_string();
        let actor_id = body["actor_id"].as_str()
            .ok_or_else(|| anyhow::anyhow!("token exchange: missing actor_id"))?.to_string();
        let permissions: Vec<String> = body["permissions"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        std::env::set_var("SOLARPLEX_SESSION_ID", &session_id);
        std::env::set_var("SOLARPLEX_ACTOR_ID", &actor_id);
        std::env::set_var("SOLARPLEX_CAP_ID", &token);
        std::env::set_var("SOLARPLEX_PERMISSIONS", serde_json::to_string(&permissions)?);
    }

    let config = Config::from_env()?;

    // A cap_id is not optional in any deployment this binary actually
    // supports — every server-facing call after this point (announce/detach,
    // the legacy approval path in approval.rs, standing-policy sync)
    // either requires one or silently degrades without one. That used to be
    // enforced only by convention (comments, `tracing::error!` calls buried
    // in individual call sites, .env.example's "not a supported path" note)
    // rather than by the code — a deployment that set SOLARPLEX_SESSION_ID/
    // SOLARPLEX_ACTOR_ID directly (skipping SOLARPLEX_TOKEN) would start up
    // looking healthy and only discover the gap per-call, at runtime, in
    // scattered ways. Fail loudly at startup instead — this is the one
    // place that can say why, once, instead of every downstream caller
    // guessing.
    let identity = config.identity();
    if identity.cap_id.is_none() {
        anyhow::bail!(
            "shim: no cap_id. SOLARPLEX_TOKEN was not exchanged (or SOLARPLEX_CAP_ID wasn't \
             otherwise set). Every supported deployment goes through the attach-token exchange; \
             starting from SOLARPLEX_SESSION_ID/SOLARPLEX_ACTOR_ID alone is not a supported \
             configuration; see .env.example."
        );
    }

    tracing::info!(session_id = %identity.session_id, actor_id = %identity.actor_id, "shim starting");

    let session = Arc::new(SessionClient::new(config.clone()));

    // NOTE: session.announce() is deliberately NOT called here. Shim starting
    // is not evidence a real agent is attached — it only proves this local
    // process launched, well before guardian/adapter exist and long before any
    // actual MCP client connects. `announce()`/`detach()` are called from the
    // AdapterMessage::ClientConnected/ClientDisconnected handlers in run_unix's
    // dispatch loop below, in response to the adapter observing a genuine SSE
    // connection open/close — the real "an agent is here" milestone.

    // Periodic liveness ping — see SessionClient::heartbeat. This is a backstop
    // for shim-process death (crash, kill -9) between real attach/detach
    // signals, not the primary liveness source. Interval must stay well under
    // the server's AGENT_STALE_THRESHOLD_SECS (ws.rs, server crate; currently
    // 3x AGENT_HEARTBEAT_INTERVAL_SECS = 45s) or a slow tick here will make a
    // healthy agent flicker to "detached". Runs for the life of the process;
    // no explicit shutdown needed since it dies with the process.
    {
        let heartbeat_session = session.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                if !heartbeat_session.heartbeat().await {
                    break;
                }
            }
        });
    }

    #[cfg(unix)]
    return run_unix(config, session).await;

    #[cfg(not(unix))]
    anyhow::bail!("solarplex-shim requires a Unix operating system");
}

#[cfg(unix)]
async fn run_unix(config: Config, session: Arc<SessionClient>) -> anyhow::Result<()> {
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::os::unix::process::CommandExt;

    // One fresh, owned snapshot for the whole function — every use below
    // reads from this local rather than re-deserializing per line.
    let identity = config.identity();

    // ── Guardian socketpair ───────────────────────────────────────────────────
    // One end stays in the shim (sv0); the other (sv1) is dup2'd to
    // GUARDIAN_IPC_FD in the guardian's pre_exec hook.
    // Fd possession IS the authority — no socket path, secret, or SO_PEERCRED.
    let (guardian_sv0, guardian_sv1) = StdUnixStream::pair()?;
    let guardian_sv1_raw = guardian_sv1.into_raw_fd();

    let guardian_bin = std::env::var("SOLARPLEX_GUARDIAN_BIN")
        .unwrap_or_else(|_| "solarplex-guardian".into());

    let mut guardian_cmd = std::process::Command::new(&guardian_bin);
    guardian_cmd
        .env("SOLARPLEX_WS",         &config.server_ws)
        .env("SOLARPLEX_SESSION_ID", &identity.session_id)
        .env("SOLARPLEX_ACTOR_ID",   &identity.actor_id)
        .stderr(std::process::Stdio::inherit());
    if std::env::var("SOLARPLEX_GUARDIAN_FAIL_OPEN").is_ok() {
        guardian_cmd.env("SOLARPLEX_GUARDIAN_FAIL_OPEN", "1");
    }
    if std::env::var("SOLARPLEX_ALLOW_UNSANDBOXED").is_ok() {
        guardian_cmd.env("SOLARPLEX_ALLOW_UNSANDBOXED", "1");
    }
    if std::env::var("SOLARPLEX_REQUIRE_IMA").is_ok() {
        guardian_cmd.env("SOLARPLEX_REQUIRE_IMA", "1");
    }
    // Forward guardian resource-limit policy overrides, same pattern as the
    // two vars above — see crates/guardian/src/resource_policy.rs. Shim's
    // environment is the deployment's environment; guardian never sees it
    // directly, only what shim explicitly passes through.
    for name in ["CPU", "AS", "FSIZE", "NOFILE", "STACK", "CORE", "NPROC"] {
        let key = format!("SOLARPLEX_RLIMIT_{name}");
        if let Ok(val) = std::env::var(&key) {
            guardian_cmd.env(&key, val);
        }
    }
    // Safety: pre_exec runs after fork, before exec, in the child process only.
    // guardian_sv1_raw is a valid fd in both parent and child post-fork.
    unsafe {
        guardian_cmd.pre_exec(move || {
            // Place sv1 at GUARDIAN_IPC_FD.  dup2 does not copy FD_CLOEXEC,
            // so the fd survives exec into the guardian binary.
            if guardian_sv1_raw != GUARDIAN_IPC_FD {
                if libc::dup2(guardian_sv1_raw, GUARDIAN_IPC_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(guardian_sv1_raw);
            } else {
                // Already at the right fd; ensure CLOEXEC is cleared.
                let flags = libc::fcntl(GUARDIAN_IPC_FD, libc::F_GETFD);
                libc::fcntl(GUARDIAN_IPC_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
    guardian_cmd.spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn guardian ({guardian_bin}): {e}"))?;
    // Close the parent's copy of sv1 — the guardian owns it now.
    unsafe { libc::close(guardian_sv1_raw); }

    // Wrap the shim's end of the guardian socket as a tokio stream.
    guardian_sv0.set_nonblocking(true)?;
    let guardian_stream = tokio::net::UnixStream::from_std(guardian_sv0)?;
    let guardian = GuardianHandle {
        socket: Arc::new(tokio::sync::Mutex::new(guardian_stream)),
    };
    tracing::info!("shim: guardian spawned, authority socket at child fd {GUARDIAN_IPC_FD}");

    // ── Adapter socketpair ────────────────────────────────────────────────────
    let (adapter_sv0, adapter_sv1) = StdUnixStream::pair()?;
    let adapter_sv1_raw = adapter_sv1.into_raw_fd();

    let adapter_bin = std::env::var("SOLARPLEX_ADAPTER_BIN")
        .unwrap_or_else(|_| "solarplex-adapter".into());

    let mut adapter_cmd = std::process::Command::new(&adapter_bin);
    adapter_cmd
        .env("SOLARPLEX_WS",         &config.server_ws)
        .env("SOLARPLEX_SESSION_ID", &identity.session_id)
        .env("SOLARPLEX_ACTOR_ID",   &identity.actor_id)
        .env("SIDECAR_PORT",         config.listen_port.to_string())
        .env("UPSTREAM_MCP_URL",     &config.upstream_mcp);
    if let Some(ref cmd_str) = config.upstream_mcp_cmd {
        adapter_cmd.env("UPSTREAM_MCP_CMD", cmd_str);
    }
    if config.fail_open {
        adapter_cmd.env("FAIL_OPEN", "1");
    }
    if let Some(ref cap_id) = identity.cap_id {
        adapter_cmd.env("SOLARPLEX_CAP_ID", cap_id);
    }
    if !identity.permissions.is_empty() {
        adapter_cmd.env("SOLARPLEX_PERMISSIONS",
            serde_json::to_string(&identity.permissions)?);
    }
    // Safety: same as guardian pre_exec above.
    unsafe {
        adapter_cmd.pre_exec(move || {
            if adapter_sv1_raw != ADAPTER_IPC_FD {
                if libc::dup2(adapter_sv1_raw, ADAPTER_IPC_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(adapter_sv1_raw);
            } else {
                let flags = libc::fcntl(ADAPTER_IPC_FD, libc::F_GETFD);
                libc::fcntl(ADAPTER_IPC_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
    adapter_cmd.spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn adapter ({adapter_bin}): {e}"))?;
    unsafe { libc::close(adapter_sv1_raw); }

    // Wrap the shim's end of the adapter socket as a tokio stream.
    adapter_sv0.set_nonblocking(true)?;
    let adapter_stream = tokio::net::UnixStream::from_std(adapter_sv0)?;
    tracing::info!("shim: adapter spawned, authority socket at child fd {ADAPTER_IPC_FD}");

    // ── Scout pool ────────────────────────────────────────────────────────────
    let scout_pool = Arc::new(scout::ScoutPool::spawn(&scout::ScoutPoolConfig::default()));

    // ── Policy ────────────────────────────────────────────────────────────────
    // The fixed auto_approve list below is only this shim's own safe-by-
    // default fallback for read-only/informational tools — server_policies
    // (fetched from whatever the session owner actually configured via
    // POST /sessions/:id/approval-policies) always wins over it. Without
    // this fetch, the legacy (non-ORB) approval path never consulted the
    // session's real configured policy at all — see policy::Policy's doc
    // comment.
    // Async fetch happens before building/sealing PolicyData -- Policy::build's
    // closure is synchronous by design (see its doc comment), so the result
    // is fetched first and moved in.
    let server_policies = session.fetch_approval_policies().await;
    tracing::info!(
        server_policy_count = server_policies.len(),
        "shim: loaded session standing policy",
    );
    let policy = policy::Policy::build(|p| {
        for name in &[
            "read_file", "list_directory", "directory_tree", "search_files",
            "get_file_info", "list_allowed_directories",
            "solarplex_session_info", "solarplex_list_artifacts",
            "solarplex_read_artifact", "solarplex_read_feed",
            "solarplex_read_context", "solarplex_read_whiteboard",
        ] {
            p.auto_approve.insert(name.to_string());
        }
        p.server_policies = server_policies;
    });

    // ── Adapter IPC: background writer ────────────────────────────────────────
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<ipc::ShimMessage>();
    let (read_half, write_half)  = tokio::io::split(adapter_stream);

    tokio::spawn(async move {
        let mut w = write_half;
        while let Some(msg) = write_rx.recv().await {
            if ipc::write_frame(&mut w, &msg).await.is_err() { break; }
        }
    });

    // ── Adapter IPC: reader + dispatcher ─────────────────────────────────────
    // No SO_PEERCRED check or ChannelHello — fd possession is the authority.
    // The kernel guarantees that only the process the shim exec'd at spawn time
    // holds the other end of this socketpair.
    let write_tx2 = write_tx.clone();
    let reader = tokio::spawn(async move {
        let mut r = read_half;
        loop {
            let msg: ipc::AdapterMessage = match ipc::read_frame(&mut r).await {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => { tracing::warn!("shim: read error: {e}"); break; }
            };

            match msg {
                ipc::AdapterMessage::Propose(req) => {
                    let config     = config.clone();
                    let sess       = session.clone();
                    let pool       = scout_pool.clone();
                    let ghandle    = guardian.clone();
                    let pol        = policy.clone();
                    let tx         = write_tx2.clone();
                    tokio::spawn(async move {
                        let decision = approval::handle_proposal(
                            req, &config, &sess, &pool, &ghandle, &pol,
                        ).await;
                        let _ = tx.send(ipc::ShimMessage::Decision(decision));
                    });
                }
                ipc::AdapterMessage::ExecDone(notice) => {
                    let sess   = session.clone();
                    let config = config.clone();
                    let tx     = write_tx2.clone();
                    tokio::spawn(async move {
                        approval::handle_exec_done(notice, sess, &config).await;
                        let _ = tx.send(ipc::ShimMessage::ExecDoneAck);
                    });
                }
                // The adapter observed a real MCP client open its SSE stream —
                // the actual "an agent is here" milestone. No ack needed; the
                // adapter isn't waiting on a reply for either of these.
                ipc::AdapterMessage::ClientConnected => {
                    let sess = session.clone();
                    tokio::spawn(async move { sess.announce().await; });
                }
                // The adapter observed its SSE stream close.
                ipc::AdapterMessage::ClientDisconnected => {
                    let sess = session.clone();
                    tokio::spawn(async move { sess.detach().await; });
                }
                // Server-authority call on the adapter's behalf — see
                // ServerCall's doc comment for why this exists instead of
                // the adapter calling the server directly.
                ipc::AdapterMessage::ServerCall(req) => {
                    let sess = session.clone();
                    let tx   = write_tx2.clone();
                    tokio::spawn(async move {
                        let (body, error) = match sess.dispatch_server_call(req.call).await {
                            Ok(v)  => (Some(v), None),
                            Err(e) => (None, Some(e)),
                        };
                        let _ = tx.send(ipc::ShimMessage::ServerCallResult(
                            ipc::ServerCallResponse { id: req.id, body, error },
                        ));
                    });
                }
            }
        }
    });

    // The shim lives as long as the adapter IPC connection is open.
    reader.await?;
    Ok(())
}
