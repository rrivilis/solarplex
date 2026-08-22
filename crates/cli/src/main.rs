mod client;
mod cmd;
mod config;
mod output;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Ctx;

/// sp — Solarplex session CLI
///
/// Bare reference dispatch: running `sp <type>/<id>` is equivalent to
///   artifact/abc123   →  sp artifact get abc123
///   approval/01JXXX   →  sp approval wait 01JXXX
///   session/01JXXX    →  sp session inspect 01JXXX
///   cap/01JXXX        →  sp cap inspect 01JXXX
#[derive(Parser)]
#[command(
    name = "sp",
    about = "Solarplex session CLI",
    version,
    // Allow the bare-ref rewrite in main() to happen before clap sees args
    // when the first arg doesn't look like a subcommand.
)]
struct Cli {
    /// API server base URL (overrides SOLARPLEX_SERVER)
    #[arg(long, env = "SOLARPLEX_SERVER", global = true, hide_env = true)]
    server: Option<String>,

    /// Session ID (overrides SOLARPLEX_SESSION_ID)
    #[arg(long = "session", env = "SOLARPLEX_SESSION_ID", global = true, hide_env = true)]
    session_id: Option<String>,

    /// Actor ID (overrides SOLARPLEX_ACTOR_ID)
    ///
    /// Deliberately NOT `env = "SOLARPLEX_ACTOR_ID"` like the other global
    /// flags above: `config::save()` exports that exact env var into
    /// `session.fish`/`session.sh` on every `session enter`/`attach`, and
    /// sourcing that file into a shell would otherwise make every later `sp`
    /// invocation in that shell look like it got an explicit `--actor` —
    /// indistinguishable from real user intent. `Ctx::load` still reads
    /// `SOLARPLEX_ACTOR_ID` itself for the general persisted-default tier;
    /// only `session enter`'s explicit-override fast path (which needs to
    /// tell "you typed --actor just now" apart from "a shell you sourced
    /// happens to have this set") skips it. See `cmd::session::enter`.
    #[arg(long = "actor", global = true)]
    actor_id: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Navigate the entity graph — read-only.
    ///
    /// ENTITY is a `type/id` ref (or a bare collection name like `sessions`)
    /// — omit it, or pass `ls`, for the root namespace. An optional
    /// FUNCTION after it shows a derived read-only view over that entity;
    /// REST holds any extra arguments that function itself needs.
    ///
    ///   sp ask                                     root namespace (same as `ls`)
    ///   sp ask sessions                             all sessions
    ///   sp ask session/42                           inspect a session (ULID or name)
    ///   sp ask session/PaymentsAllocation            session resolved via name→ULID
    ///   sp ask session/42 pending-approvals          derived view — same for artifacts | members | caps | context | epoch
    ///   sp ask actor/alice                           actor view
    ///   sp ask actor/alice why approval/01J...       why alice can/can't act on this approval
    ///   sp ask cap/01J... lineage                    delegation chain for a cap
    ///   sp ask artifact/01J...                       artifact content
    ///
    /// Mutations never go through `ask` — see `sp act --help`.
    #[command(verbatim_doc_comment)]
    Ask(cmd::ask::AskArgs),
    /// Fire a transition on an entity — the write path.
    ///
    /// ENTITY identifies what to act on; TRANSITION is the PascalCase
    /// operation name; the flags below supply its arguments (each flag's
    /// own help lists which transition it applies to — only set the ones
    /// relevant to the one you're running).
    ///
    ///   sp act session New --name "Payments Q3" --policy majority
    ///   sp act session/42 OwnershipTransfer --to bob
    ///   sp act session/42 Delegate --to agent-01J --ttl 900 --permissions bash_exec,read_file
    ///   sp act session/42 CreateArtifact --name report.md --type document --file ./report.md
    ///   sp act session/42 AddContext decision we chose postgres for the queue
    ///   sp act session/42 Pause
    ///   sp act session/42 Archive
    ///   sp act cap/01J... Revoke --strategy cap --drain 30
    ///   sp act approval/01J... Grant
    ///   sp act approval/01J... Deny
    ///
    /// `sp ask` is the read-only counterpart — no mutation ever goes through it.
    #[command(verbatim_doc_comment)]
    Act(cmd::act::ActArgs),
    /// Sign in via the browser (stores an sp_token for subsequent commands)
    Login(cmd::login::LoginArgs),
    /// Sign out and clear the stored sp_token
    Logout(cmd::login::LogoutArgs),
    /// List, create, and manage sessions
    Session(cmd::session::SessionArgs),
    /// Show an actor's sessions and activity
    Actor(cmd::actor::ActorArgs),
    /// Delegate capability tokens to agents
    Cap(cmd::cap::CapArgs),
    /// View and decide on pending approvals
    Approval(cmd::approval::ApprovalArgs),
    /// Create and inspect artifacts
    Artifact(cmd::artifact::ArtifactArgs),
    /// Add context entries to the session
    Context(cmd::context::ContextArgs),
    /// Your personal inbox — mostly session invites addressed to you
    Mailbox(cmd::mailbox::MailboxArgs),
    /// Preview, redeem, create, and revoke session invites
    Invite(cmd::invite::InviteArgs),
    /// Query the authorization state: why / who-can / lineage
    Auth(cmd::auth::AuthArgs),
    /// Live cursor-oriented event stream: sp watch [session/<id>] [--from 0] [--json]
    Watch(cmd::watch::WatchArgs),
    /// Causal explanation of session state, from the cursor position.
    ///
    /// Read-only backward traversal of the event log — never mutates state.
    /// The cursor pins the observation frame: the explanation covers events
    /// 0..cursor.seq, the same window `sp watch` has already observed.
    ///
    ///   sp why                    session-level causal summary
    ///   sp why policy              why current policy says what it does
    ///   sp why bundle/<id>         why this bundle was gated/rejected/deferred
    ///   sp why approval/<id>       why this approval was requested and how resolved
    ///   sp why saga/<id>           why this saga is in its current state
    ///   sp why --session <name>    explicit session (default: attached)
    #[command(verbatim_doc_comment)]
    Why(cmd::why::WhyArgs),
    /// Interactive TUI dashboard: browse sessions live, alongside (not instead
    /// of) the one-shot commands above. Navigation and hotkeys only in this
    /// first cut -- no typed command-input line.
    #[command(name = "shell")]
    Tui,
    /// Route a URI/text/ULID through plumbing rules
    Plumb(cmd::plumb::PlumbArgs),
    /// Resolve a bare ULID to its entity type and display it
    Resolve {
        id: String,
    },
    /// Internal: shell adapter (used by the fish plugin)
    #[command(name = "_shell", hide = true)]
    Shell(cmd::shell::ShellArgs),
    /// Internal: install solarplex: URI handler (.desktop + xdg-mime)
    #[command(name = "_install_uri_handler", hide = true)]
    InstallUriHandler,
    /// Internal: write default ~/.config/solarplex/plumb.toml
    #[command(name = "_init_plumb", hide = true)]
    InitPlumb,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Suppress broken-pipe panics: when stdout is piped to a reader that exits
    // early (e.g. `sp session enter ID | source` in bash, or `sp ls | head`),
    // Rust's default println! panics with "Broken pipe".  Exit 0 instead.
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string();
        if msg.contains("Broken pipe") || msg.contains("os error 32") {
            std::process::exit(0);
        }
        eprintln!("{info}");
        std::process::exit(1);
    }));

    // Initialise tracing only when RUST_LOG is set, so normal CLI usage is clean.
    // Writer is stderr, not the default stdout: `sp shell` renders its TUI to
    // stdout via the alternate screen, and tracing output landing on the same
    // stream corrupts that render instead of appearing as separate log lines.
    if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .init();
    }

    // ── Bare-reference dispatch ──────────────────────────────────────────────
    // Rewrite `sp artifact/abc123` → `sp artifact get abc123` before clap parses.
    let argv: Vec<String> = std::env::args().collect();
    let argv = rewrite_bare_ref(argv);

    let cli = Cli::parse_from(&argv);

    let ctx = Ctx::load(cli.server, cli.session_id, cli.actor_id);

    match cli.command {
        Commands::Ask(a)      => cmd::ask::run(a, &ctx).await?,
        Commands::Act(a)      => cmd::act::run(a, &ctx).await?,
        Commands::Login(a)    => cmd::login::run_login(a, &ctx).await?,
        Commands::Logout(a)   => cmd::login::run_logout(a, &ctx).await?,
        Commands::Session(a)  => cmd::session::run(a, &ctx).await?,
        Commands::Actor(a)    => cmd::actor::run(a, &ctx).await?,
        Commands::Cap(a)      => cmd::cap::run(a, &ctx).await?,
        Commands::Approval(a) => cmd::approval::run(a, &ctx).await?,
        Commands::Artifact(a) => cmd::artifact::run(a, &ctx).await?,
        Commands::Context(a)  => cmd::context::run(a, &ctx).await?,
        Commands::Mailbox(a)  => cmd::mailbox::run(a, &ctx).await?,
        Commands::Invite(a)   => cmd::invite::run(a, &ctx).await?,
        Commands::Auth(a)     => cmd::auth::run(a, &ctx).await?,
        Commands::Watch(a)    => cmd::watch::run(a, &ctx).await?,
        Commands::Why(a)      => cmd::why::run(a, &ctx).await?,
        Commands::Tui         => tui::run(&ctx).await?,
        Commands::Plumb(a)    => cmd::plumb::run(a, &ctx).await?,
        Commands::Resolve { id } => {
            cmd::plumb::run(
                cmd::plumb::PlumbArgs {
                    cmd: cmd::plumb::PlumbCmd::Resolve { id },
                },
                &ctx,
            ).await?
        }
        Commands::Shell(a)    => cmd::shell::run(a, &ctx).await?,
        Commands::InstallUriHandler => cmd::plumb::install_uri_handler()?,
        Commands::InitPlumb         => cmd::plumb::write_default_plumb_config()?,
    }

    Ok(())
}

/// Rewrite `sp [flags] <type>/<id>` → `sp [flags] <type> <verb> <id>`.
///
/// Middle-click / Acme-style: any bare entity reference is a valid command.
/// We scan past leading `--flag value` pairs to find the first positional arg.
fn rewrite_bare_ref(mut argv: Vec<String>) -> Vec<String> {
    if argv.len() < 2 {
        return argv;
    }

    // Find the index of the first non-flag positional argument.
    // Global flags we know take a value: --server, --session, --actor
    let value_flags: &[&str] = &["--server", "--session", "--actor"];
    let mut i = 1usize;
    while i < argv.len() {
        let arg = &argv[i];
        if arg.starts_with('-') {
            // Flag — skip it and optionally its value
            if value_flags.iter().any(|f| arg == f) {
                i += 2; // skip flag + value
            } else if let Some(_) = arg.find('=') {
                i += 1; // --flag=value form, value embedded
            } else {
                i += 1; // boolean flag
            }
        } else {
            break; // first positional
        }
    }

    if i >= argv.len() {
        return argv;
    }

    let first = argv[i].clone();

    if first.contains('/') {
        // word/id or word/ form — route known entity types through `sp ask`.
        if let Some((kind, id)) = first.split_once('/') {
            if id.is_empty() { return argv; }
            let known = matches!(kind,
                "session" | "actor" | "cap" | "approval" | "artifact" | "context"
            );
            if known {
                // `sp session/42` → `sp ask session/42`
                argv.splice(i..i+1, ["ask".to_string(), first]);
            } else {
                // Unknown type/id → plumb (handles solarplex: URIs, custom schemes, etc.)
                let bare = argv[i].clone();
                argv.splice(i..i+1, ["plumb".to_string(), "run".to_string(), bare]);
            }
        }
    } else {
        // Bare 26-char ULID (no slash) → `sp ask <id>` (ask resolves the type)
        let is_ulid = first.len() == 26
            && first.chars().all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c));
        if is_ulid {
            argv.splice(i..i+1, ["ask".to_string(), first]);
        }
    }
    argv
}
