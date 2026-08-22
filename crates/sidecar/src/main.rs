mod artifact_scan;
mod metrics_route;
mod proxy;
mod yara_scan;

use std::collections::HashMap;

// The shim places one end of a socketpair at this fd before exec-ing the adapter.
// Matches ADAPTER_IPC_FD in shim/src/main.rs.
const ADAPTER_IPC_FD: i32 = 3;

#[derive(Clone)]
pub struct Config {
    pub server_ws:        String,
    pub session_id:       String,
    pub actor_id:         String,
    pub listen_port:      u16,
    pub upstream_mcp:     String,
    pub upstream_mcp_cmd: Option<String>,
    // shim_ipc_path and channel_secret removed — authority is the inherited fd.
    pub cap_id:           Option<String>,
    pub tool_categories:  HashMap<String, String>,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let tool_categories: HashMap<String, String> = std::env::var("SOLARPLEX_TOOL_CATEGORIES")
            .ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        Ok(Self {
            server_ws:      std::env::var("SOLARPLEX_WS")
                .unwrap_or_else(|_| "ws://localhost:8080".into()),
            session_id:     std::env::var("SOLARPLEX_SESSION_ID")?,
            actor_id:       std::env::var("SOLARPLEX_ACTOR_ID")?,
            listen_port:    std::env::var("SIDECAR_PORT")
                .unwrap_or_else(|_| "7777".into()).parse()?,
            upstream_mcp:   std::env::var("UPSTREAM_MCP_URL").unwrap_or_default(),
            upstream_mcp_cmd: std::env::var("UPSTREAM_MCP_CMD").ok(),
            cap_id:         std::env::var("SOLARPLEX_CAP_ID").ok(),
            tool_categories,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "solarplex_adapter=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    tracing::info!(
        session_id = %config.session_id,
        actor_id   = %config.actor_id,
        "adapter starting on inherited fd {ADAPTER_IPC_FD}"
    );

    // Open the pre-established IPC socket inherited from the shim (no connect, no handshake).
    let shim = proxy::ShimClient::from_inherited_fd(ADAPTER_IPC_FD)?;
    let prometheus_handle = metrics_route::install_or_reuse_recorder();
    proxy::serve(config, shim, prometheus_handle).await?;
    Ok(())
}
