//! Layer 4 delivery glue: the one binary that touches disk on behalf of
//! `secrets-ratchet` (rotation) and `secrets-store` (age encryption).
//! Four moments, four subcommands:
//! - `init` — operator bootstraps a brand-new ratchet chain.
//! - `encrypt` — operator hand-encrypts a bundle (out-of-band bootstrap,
//!   or re-keying recipients without rotating credentials).
//! - `rotate` — operator advances the ratchet and re-encrypts both the
//!   credential bundle and the ratchet's own persisted state.
//! - `decrypt` — runs on the target host as `ExecStartPre`, turning
//!   `secrets.age` into the `EnvironmentFile=` systemd reads.
//!
//! `encrypt-bytes`/`decrypt-bytes` are a fifth, deliberately separate pair:
//! `CredentialBundle` is a fixed 3-field shape (database_url,
//! oidc_client_id, oidc_client_secret) baked into `encrypt`/`decrypt`/
//! `rotate` above — it does not rotate through the ratchet the way
//! `database_url`/`oidc_client_secret` do, and it has no opinion about
//! what's inside beyond "bytes." Used for secrets that want the same
//! TPM-sealed/age delivery pipeline but don't fit that fixed shape and
//! don't share its rotation cadence — e.g. backup object-store credentials
//! (see deploy/scripts/backup-postgres.sh), which rotate on the storage
//! provider's own schedule, not the DB-password ratchet's.
//!
//! Identities are always passed via `--*-env` environment variables
//! (never bare CLI args — args land in `ps`/shell history, env vars set
//! by systemd's own `Environment=` or an operator's shell do not).
//!
//! This binary contains no hardware-plugin shelling code itself:
//! `secrets_store::parse_identity`/`parse_recipient` only accept the
//! software/X25519 string form today. Swapping in a hardware-backed
//! identity (YubiKey, TPM) is a config-level change at the identity
//! string's source, not a code change here — see `secrets-store`'s doc
//! comment for why the encrypt/decrypt primitives are already written
//! generically enough for that.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use age::{Identity, Recipient};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use secrets_ratchet::RatchetState;
use secrets_store::{decrypt_bundle, decrypt_bytes, encrypt_bundle, encrypt_bytes, parse_identity, parse_recipient, CredentialBundle};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "secrets-cli", about = "Solarplex secrets: age encryption + ratchet rotation glue")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap a brand-new ratchet chain (genesis epoch) and persist it,
    /// encrypted, to `--state-out`.
    Init {
        #[arg(long)]
        state_out: PathBuf,
        /// age1... recipient strings, repeatable (operator key, recovery key, ...).
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
    },
    /// Encrypt a credential bundle to one or more recipients directly,
    /// bypassing the ratchet (bootstrap, or re-keying recipients).
    Encrypt {
        #[arg(long, env = "SOLARPLEX_DATABASE_URL")]
        database_url: String,
        #[arg(long, env = "SOLARPLEX_OIDC_CLIENT_ID")]
        oidc_client_id: String,
        #[arg(long, env = "SOLARPLEX_OIDC_CLIENT_SECRET")]
        oidc_client_secret: String,
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Decrypt `secrets.age` into a systemd EnvironmentFile. Intended to
    /// run as `ExecStartPre` against a runtime-only (tmpfs) output path.
    Decrypt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, env = "SOLARPLEX_AGE_IDENTITY")]
        identity: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Advance the ratchet one epoch: re-encrypts both the ratchet's own
    /// state (`--state-out`) and the credential bundle it derives
    /// (`--secrets-out`). The old on-disk state file is left alone —
    /// callers decide when to replace `--state-in` with `--state-out`'s
    /// output (they may be the same path).
    Rotate {
        #[arg(long)]
        state_in: PathBuf,
        #[arg(long)]
        state_out: PathBuf,
        #[arg(long)]
        secrets_out: PathBuf,
        #[arg(long, env = "SOLARPLEX_AGE_IDENTITY")]
        identity: String,
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        /// `{password}` is substituted with the freshly-derived db password.
        #[arg(long)]
        database_url_template: String,
        #[arg(long, env = "SOLARPLEX_OIDC_CLIENT_ID")]
        oidc_client_id: String,
    },
    /// Encrypt an arbitrary file's raw bytes to one or more recipients —
    /// for secrets that don't fit `CredentialBundle`'s fixed shape. The
    /// caller owns the format of what's inside `--in` (e.g. a KEY=VALUE
    /// env file); this subcommand only ever sees bytes.
    EncryptBytes {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Decrypt an `encrypt-bytes`-produced file back to raw bytes at
    /// `--out`. Intended to run as `ExecStartPre` against a runtime-only
    /// (tmpfs) output path, same as `decrypt`, but for a second,
    /// independent ciphertext artifact rather than `secrets.age` itself.
    DecryptBytes {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, env = "SOLARPLEX_AGE_IDENTITY")]
        identity: String,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { state_out, recipients } => cmd_init(&state_out, &recipients),
        Command::Encrypt { database_url, oidc_client_id, oidc_client_secret, recipients, out } => {
            cmd_encrypt(database_url, oidc_client_id, oidc_client_secret, &recipients, &out)
        }
        Command::Decrypt { input, identity, out } => cmd_decrypt(&input, &identity, &out),
        Command::Rotate {
            state_in,
            state_out,
            secrets_out,
            identity,
            recipients,
            database_url_template,
            oidc_client_id,
        } => cmd_rotate(
            &state_in,
            &state_out,
            &secrets_out,
            &identity,
            &recipients,
            &database_url_template,
            oidc_client_id,
        ),
        Command::EncryptBytes { input, recipients, out } => cmd_encrypt_bytes(&input, &recipients, &out),
        Command::DecryptBytes { input, identity, out } => cmd_decrypt_bytes(&input, &identity, &out),
    }
}

fn cmd_init(state_out: &Path, recipients: &[String]) -> Result<()> {
    let parsed = parse_recipients(recipients)?;
    let refs = recipient_refs(&parsed);

    let mut genesis = secrets_ratchet::fresh_entropy();
    let armored = encrypt_bytes(&genesis, &refs)?;
    genesis.zeroize();

    write_new_file(state_out, armored.as_bytes())?;
    println!("initialized ratchet state at {}", state_out.display());
    Ok(())
}

fn cmd_encrypt(
    database_url: String,
    oidc_client_id: String,
    oidc_client_secret: String,
    recipients: &[String],
    out: &Path,
) -> Result<()> {
    let bundle = CredentialBundle { database_url, oidc_client_id, oidc_client_secret };
    let parsed = parse_recipients(recipients)?;
    let refs = recipient_refs(&parsed);

    let armored = encrypt_bundle(&bundle, &refs)?;
    write_new_file(out, armored.as_bytes())?;
    println!("wrote {}", out.display());
    Ok(())
}

fn cmd_decrypt(input: &Path, identity: &str, out: &Path) -> Result<()> {
    let armored = fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
    let id = parse_identity(identity)?;
    let bundle = decrypt_bundle(&armored, &id as &dyn Identity)?;

    let contents = format!(
        "DATABASE_URL={}\nOIDC_CLIENT_ID={}\nOIDC_CLIENT_SECRET={}\n",
        bundle.database_url, bundle.oidc_client_id, bundle.oidc_client_secret
    );
    write_new_file(out, contents.as_bytes())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_rotate(
    state_in: &Path,
    state_out: &Path,
    secrets_out: &Path,
    identity: &str,
    recipients: &[String],
    database_url_template: &str,
    oidc_client_id: String,
) -> Result<()> {
    if !database_url_template.contains("{password}") {
        bail!("--database-url-template must contain a {{password}} placeholder");
    }

    let armored_state =
        fs::read_to_string(state_in).with_context(|| format!("reading {}", state_in.display()))?;
    let id = parse_identity(identity)?;

    let mut current_bytes = decrypt_bytes(&armored_state, &id as &dyn Identity)?;
    if current_bytes.len() != 32 {
        current_bytes.zeroize();
        bail!("stored ratchet state is {} bytes, expected 32 — refusing to proceed", current_bytes.len());
    }
    let mut state_arr = [0u8; 32];
    state_arr.copy_from_slice(&current_bytes);
    current_bytes.zeroize();

    let current = RatchetState::genesis(state_arr);
    let fresh = secrets_ratchet::fresh_entropy();
    let next = current.advance(fresh);

    let db_password = next.derive_credential_string("solarplex-db-password-v1", 32);
    let oidc_secret = next.derive_credential_string("solarplex-oidc-secret-v1", 32);

    let parsed = parse_recipients(recipients)?;
    let refs = recipient_refs(&parsed);

    let bundle = CredentialBundle {
        database_url: database_url_template.replace("{password}", &db_password),
        oidc_client_id,
        oidc_client_secret: oidc_secret,
    };
    let secrets_armored = encrypt_bundle(&bundle, &refs)?;

    let mut next_bytes = next.export_for_storage();
    let state_armored = encrypt_bytes(&next_bytes, &refs)?;
    next_bytes.zeroize();

    // Write the new state before the new bundle: if this process dies
    // between the two writes, the worst outcome is re-deriving the same
    // bundle from the same (already-persisted) next epoch on retry —
    // never a bundle whose epoch was never durably recorded.
    write_new_file(state_out, state_armored.as_bytes())?;
    write_new_file(secrets_out, secrets_armored.as_bytes())?;

    println!("rotated: {} , {}", state_out.display(), secrets_out.display());
    Ok(())
}

fn cmd_encrypt_bytes(input: &Path, recipients: &[String], out: &Path) -> Result<()> {
    let mut plaintext = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let parsed = parse_recipients(recipients)?;
    let refs = recipient_refs(&parsed);

    let armored = encrypt_bytes(&plaintext, &refs)?;
    plaintext.zeroize();

    write_new_file(out, armored.as_bytes())?;
    println!("wrote {}", out.display());
    Ok(())
}

fn cmd_decrypt_bytes(input: &Path, identity: &str, out: &Path) -> Result<()> {
    let armored = fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
    let id = parse_identity(identity)?;

    let mut plaintext = decrypt_bytes(&armored, &id as &dyn Identity)?;
    write_new_file(out, &plaintext)?;
    plaintext.zeroize();
    Ok(())
}

fn parse_recipients(recipients: &[String]) -> Result<Vec<age::x25519::Recipient>> {
    if recipients.is_empty() {
        bail!("at least one --recipient is required");
    }
    recipients
        .iter()
        .map(|s| parse_recipient(s).map_err(anyhow::Error::from))
        .collect()
}

fn recipient_refs(recipients: &[age::x25519::Recipient]) -> Vec<&dyn Recipient> {
    recipients.iter().map(|r| r as &dyn Recipient).collect()
}

/// Write `contents` to `path`, creating or truncating it, with `0600`
/// permissions — a decrypted EnvironmentFile or a ciphertext artifact
/// should never be readable by anyone but the owner. `.mode(0o600)` only
/// governs permissions at *creation*; if `path` already existed with
/// looser permissions (e.g. left over from a different process/umask),
/// `set_permissions` after the fact closes that gap explicitly rather
/// than assuming the create-time mode was the only time it mattered.
fn write_new_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(contents).with_context(|| format!("writing {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", path.display()))?;
    Ok(())
}
