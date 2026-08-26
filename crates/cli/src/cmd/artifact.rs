use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use super::session;
use crate::{client::Client, config::Ctx, output::*};

#[derive(Args)]
pub struct ArtifactArgs {
    #[command(subcommand)]
    pub cmd: ArtifactCmd,
}

#[derive(Subcommand)]
pub enum ArtifactCmd {
    /// List artifacts in the current session
    Ls,
    /// Show an artifact's content
    Get {
        /// Artifact ID or short prefix
        id: String,
        /// Save content to a file instead of printing
        #[arg(long, short)]
        save: Option<PathBuf>,
    },
    /// Create an artifact from a file or stdin
    Create {
        #[arg(long, short)]
        name: String,
        /// Type: document | code | plan | report | other
        #[arg(long, short = 't', default_value = "document")]
        r#type: String,
        #[arg(long, short)]
        file: Option<PathBuf>,
    },
    /// Import an artifact from a linked session — a real independent copy,
    /// not a live reference (see `sp session remote` for read-only cross-
    /// session viewing without copying). Auto-adds a context entry in the
    /// current session recording provenance (source session, original
    /// author, import receipt).
    Import {
        /// Artifact ID (or prefix) in the source session
        artifact_id: String,
        /// Session to import from (ULID, prefix, or name) — must already be linked
        #[arg(long = "from-session")]
        from_session: String,
    },
}

pub async fn run(args: ArtifactArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;
    match args.cmd {
        ArtifactCmd::Ls => ls(&client, ctx).await,
        ArtifactCmd::Get { id, save } => get(&client, ctx, &id, save.as_deref()).await,
        ArtifactCmd::Create { name, r#type, file } => {
            create(&client, ctx, &name, &r#type, file.as_deref()).await
        }
        ArtifactCmd::Import {
            artifact_id,
            from_session,
        } => import(&client, ctx, &artifact_id, &from_session).await,
    }
}

pub async fn ls(client: &Client, ctx: &Ctx) -> Result<()> {
    let session_id = ctx.require_session()?;
    let rows = client.list_artifacts(session_id).await?;
    let arr = rows.as_array().cloned().unwrap_or_default();

    if arr.is_empty() {
        println!("{}", dim("No artifacts."));
        return Ok(());
    }

    println!(
        "  {}  {}  {}  {}",
        bold(&pad("ARTIFACT", 10)),
        bold(&pad("NAME", 32)),
        bold(&pad("TYPE", 16)),
        bold("CREATED BY"),
    );
    for a in &arr {
        print_artifact_row(a, ctx, session_id);
    }
    Ok(())
}

// SANITIZATION AUDIT — print_artifact_row():
// id is a ULID (safe). name, typ, by are FOREIGN (actor-supplied).
fn print_artifact_row(a: &Value, ctx: &Ctx, session_id: &str) {
    let id = a["id"].as_str().unwrap_or("?"); // ULID — safe
    let name = sanitize_terminal(a["name"].as_str().unwrap_or("?")); // FOREIGN
    let typ = sanitize_terminal(a["type"].as_str().unwrap_or("other")); // FOREIGN
    let by = sanitize_terminal(a["created_by"].as_str().unwrap_or("?")); // FOREIGN
    let link = entity_link("artifact", id, session_id, &ctx.ui);
    println!(
        "  {}  {}  {}  {}",
        pad(&link, 10),
        pad(&name, 32),
        pad(&typ, 16),
        actor_link(&by)
    );
}

pub async fn get(
    client: &Client,
    ctx: &Ctx,
    id: &str,
    save: Option<&std::path::Path>,
) -> Result<()> {
    let session_id = ctx.require_session()?;

    // Resolve short prefix → full ULID
    let artifact_id = if id.len() < 26 {
        let rows = client.list_artifacts(session_id).await?;
        rows.as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|a| a["id"].as_str().map(|s| s.starts_with(id)).unwrap_or(false))
            })
            .and_then(|a| a["id"].as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| id.to_string())
    } else {
        id.to_string()
    };

    // SANITIZATION AUDIT — get():
    // artifact_id is a ULID (safe). name, mime, by are FOREIGN (actor-supplied).
    // Decoded content is the highest-risk path: up to 60 lines of arbitrary bytes
    // from whoever created the artifact — each line must be sanitized individually.
    let a = client.get_artifact(session_id, &artifact_id).await?;
    let name = sanitize_terminal(a["name"].as_str().unwrap_or("?")); // FOREIGN
    let mime = sanitize_terminal(a["type"].as_str().unwrap_or("application/octet-stream")); // FOREIGN
    let by = sanitize_terminal(a["created_by"].as_str().unwrap_or("?")); // FOREIGN
    let storage = a["storage_ref"].as_str().unwrap_or(""); // decoded below, not printed raw

    // ── Decode the data URI ──────────────────────────────────────────────────
    let (decoded_mime, bytes) = decode_storage_ref(storage);
    let effective_mime = if decoded_mime.is_empty() {
        &mime
    } else {
        &decoded_mime
    };
    let is_text = is_text_mime(effective_mime);
    let byte_len = bytes.len();

    // ── Header ───────────────────────────────────────────────────────────────
    println!();
    println!(
        "  {} {}",
        bold(&name),
        entity_link("artifact", &artifact_id, session_id, &ctx.ui)
    );
    println!("  type:  {effective_mime}");
    println!("  by:    {}", actor_link(&by));
    println!("  size:  {} bytes", byte_len);
    println!();

    // ── Save to file ─────────────────────────────────────────────────────────
    if let Some(path) = save {
        std::fs::write(path, &bytes)?;
        println!("{} Saved to {}", green("✓"), path.display());
        return Ok(());
    }

    // ── Display ───────────────────────────────────────────────────────────────
    if is_text {
        let text = String::from_utf8_lossy(&bytes);
        let lines: Vec<&str> = text.lines().collect();
        let limit = 60usize;
        for line in lines.iter().take(limit) {
            // FOREIGN: sanitize every line — artifact content is the primary
            // terminal-injection surface (60 lines of attacker-authored text).
            println!("  {}", sanitize_terminal(line));
        }
        if lines.len() > limit {
            println!();
            println!(
                "  {} {} more lines — use --save FILE to write full content",
                dim("…"),
                lines.len() - limit
            );
        }
    } else {
        println!("  {} binary content ({effective_mime})", dim("["));
        println!(
            "  Use {} to save to disk.",
            cyan(&format!("sp artifact get {id} --save FILENAME"))
        );
    }
    println!();
    Ok(())
}

pub async fn import(
    client: &Client,
    ctx: &Ctx,
    artifact_ref: &str,
    from_session_ref: &str,
) -> Result<()> {
    let target_id = ctx.require_session()?;
    let source_id = session::resolve_session_id(client, from_session_ref).await?;

    // Resolve short prefix within the SOURCE session, not the current one.
    let artifact_id = if artifact_ref.len() < 26 {
        let rows = client.list_artifacts(&source_id).await?;
        rows.as_array()
            .and_then(|arr| {
                arr.iter().find(|a| {
                    a["id"]
                        .as_str()
                        .map(|s| s.starts_with(artifact_ref))
                        .unwrap_or(false)
                })
            })
            .and_then(|a| a["id"].as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                anyhow::anyhow!("no artifact matching `{artifact_ref}` in {source_id}")
            })?
    } else {
        artifact_ref.to_string()
    };

    let data = client
        .import_artifact(target_id, &source_id, &artifact_id)
        .await?;
    let new_artifact = &data["artifact"];
    let new_id = new_artifact["id"].as_str().unwrap_or("?");
    let name = sanitize_terminal(new_artifact["name"].as_str().unwrap_or("?"));
    let already = data["already_imported"].as_bool().unwrap_or(false);

    if already {
        println!(
            "{} {} was already imported as {} — no duplicate created",
            dim("·"),
            bold(&name),
            entity_link("artifact", new_id, target_id, &ctx.ui)
        );
    } else {
        println!(
            "{} Imported {} as {}",
            green("✓"),
            bold(&name),
            entity_link("artifact", new_id, target_id, &ctx.ui)
        );
        println!(
            "{}",
            dim("A context entry recording provenance was added automatically.")
        );
    }
    Ok(())
}

/// Parse a `data:[mime][;base64],<data>` URI.
/// Returns (mime, raw_bytes).  If the string is not a data URI, treat as raw text.
fn decode_storage_ref(storage_ref: &str) -> (String, Vec<u8>) {
    if let Some(rest) = storage_ref.strip_prefix("data:") {
        if let Some(comma) = rest.find(',') {
            let meta = &rest[..comma];
            let data = &rest[comma + 1..];
            let (mime_part, is_b64) = if let Some(m) = meta.strip_suffix(";base64") {
                (m, true)
            } else {
                (meta, false)
            };
            let mime = mime_part.to_string();
            let bytes = if is_b64 {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .unwrap_or_else(|_| data.as_bytes().to_vec())
            } else {
                // URL-encoded text — decode percent-encoding
                let decoded = percent_decode(data);
                decoded.into_bytes()
            };
            return (mime, bytes);
        }
    }
    // Not a data URI — treat as plain text content
    (String::new(), storage_ref.as_bytes().to_vec())
}

/// Minimal percent-decode (handles %XX sequences).
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_text_mime(mime: &str) -> bool {
    let m = mime.split(';').next().unwrap_or(mime).trim();
    m.starts_with("text/")
        || m == "application/json"
        || m == "application/xml"
        || m == "application/javascript"
        || m == "application/typescript"
        || m.ends_with("+json")
        || m.ends_with("+xml")
        || m.ends_with("+yaml")
        || m == "application/yaml"
        || m == "application/toml"
        || m == "application/csv"
        || m == "image/svg+xml"
}

pub async fn create(
    client: &Client,
    ctx: &Ctx,
    name: &str,
    artifact_type: &str,
    file: Option<&std::path::Path>,
) -> Result<()> {
    let session_id = ctx.require_session()?;
    let actor_id = ctx.require_actor()?;

    let content = if let Some(path) = file {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?
    } else {
        use std::io::Read as _;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    };

    let a = client
        .create_artifact(session_id, actor_id, name, artifact_type, &content)
        .await?;
    let id = a["id"].as_str().unwrap_or("?");
    let link = entity_link("artifact", id, session_id, &ctx.ui);

    println!("{} Created {}", green("✓"), link);
    println!("  id:   {}", dim(id));
    println!("  name: {}", bold(name));
    println!("  type: {artifact_type}");
    println!("  size: {} bytes", content.len());
    Ok(())
}
