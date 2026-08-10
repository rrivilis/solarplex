//! Guardian-side resource-limit policy — host-protection/scheduling
//! ceilings, deliberately kept separate from `protocol::effects::DeclaredEffects`.
//!
//! `DeclaredEffects` describes the approved operation's semantic authority:
//! what it may touch. This describes infrastructure capacity: how much the
//! guardian deployment is willing to spend running it. Folding the two
//! together would make the effect vocabulary responsible for host-capacity
//! decisions it has no business making, so this stays a separate,
//! guardian-local concept. Per-approval resource *requests* are a plausible
//! future extension — a separate authorization concept to design
//! deliberately later, not bolted on here.
//!
//! Layered lowest-to-highest precedence:
//!   1. `/etc/solarplex/guardian.toml`'s `[resource_limits]` table
//!   2. `SOLARPLEX_RLIMIT_<NAME>` environment variables
//!   3. `--rlimit NAME=VALUE` guardian startup flags
//!
//! Each source accepts either `VALUE` (soft == hard) or `SOFT:HARD` — see
//! `sandbox_entry::parse_pair`. `executor.rs` reads `effective_limits()`
//! once per exec and re-emits it as `--rlimit` args on the `sandbox-entry`
//! invocation it constructs, so this module never calls `setrlimit` itself.
//!
//! A missing or malformed source is logged and skipped, not fatal: unlike
//! landlock/seccomp/rlimit-*application* in `sandbox_entry.rs` (an
//! authority boundary, fatal by design there), this is a best-effort
//! ceiling — see the module doc above for why the two are held to
//! different standards.
#![allow(dead_code)]

use crate::sandbox_entry::{self, ResourceLimits, RlimitPair};
use std::sync::OnceLock;

const CONFIG_PATH: &str = "/etc/solarplex/guardian.toml";

static EFFECTIVE: OnceLock<ResourceLimits> = OnceLock::new();

/// The effective resource-limit ceiling for this guardian deployment,
/// loaded once (file → env → flags) and cached for the process lifetime.
pub(crate) fn effective_limits() -> &'static ResourceLimits {
    EFFECTIVE.get_or_init(load)
}

fn load() -> ResourceLimits {
    let mut limits = ResourceLimits::default();
    apply_toml_file(&mut limits);
    apply_env(&mut limits);
    apply_flags(&mut limits);
    limits
}

fn apply_toml_file(limits: &mut ResourceLimits) {
    let text = match std::fs::read_to_string(CONFIG_PATH) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!("resource_policy: cannot read {CONFIG_PATH}: {e} — skipping");
            return;
        }
    };
    let cfg: TomlConfig = match toml::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("resource_policy: cannot parse {CONFIG_PATH}: {e} — skipping");
            return;
        }
    };
    let r = cfg.resource_limits;
    if let Some(p) = r.cpu           { let _ = sandbox_entry::set_named(limits, "cpu", p); }
    if let Some(p) = r.address_space { let _ = sandbox_entry::set_named(limits, "as", p); }
    if let Some(p) = r.fsize         { let _ = sandbox_entry::set_named(limits, "fsize", p); }
    if let Some(p) = r.nofile        { let _ = sandbox_entry::set_named(limits, "nofile", p); }
    if let Some(p) = r.stack         { let _ = sandbox_entry::set_named(limits, "stack", p); }
    if let Some(p) = r.core          { let _ = sandbox_entry::set_named(limits, "core", p); }
    if let Some(p) = r.nproc         { let _ = sandbox_entry::set_named(limits, "nproc", p); }
}

fn apply_env(limits: &mut ResourceLimits) {
    for &name in sandbox_entry::RLIMIT_NAMES {
        let key = format!("SOLARPLEX_RLIMIT_{}", name.to_uppercase());
        let Ok(val) = std::env::var(&key) else { continue };
        match sandbox_entry::parse_pair(&val) {
            Ok(pair) => { let _ = sandbox_entry::set_named(limits, name, pair); }
            Err(e) => tracing::warn!("resource_policy: {key}={val:?}: {e} — skipping"),
        }
    }
}

fn apply_flags(limits: &mut ResourceLimits) {
    // Guardian's own argv (the outer process this module runs in) — distinct
    // from `sandbox-entry`'s argv, which is a separate process bwrap spawns
    // and never reaches this module.
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--rlimit" {
            if let Some(val) = args.get(i + 1) {
                if let Err(e) = sandbox_entry::apply_rlimit_arg(limits, val) {
                    tracing::warn!("resource_policy: --rlimit {val:?}: {e} — skipping");
                }
                i += 1;
            }
        }
        i += 1;
    }
}

#[derive(serde::Deserialize, Default)]
struct TomlConfig {
    #[serde(default)]
    resource_limits: TomlResourceLimits,
}

#[derive(serde::Deserialize, Default)]
struct TomlResourceLimits {
    cpu: Option<RlimitPair>,
    #[serde(rename = "as")]
    address_space: Option<RlimitPair>,
    fsize:  Option<RlimitPair>,
    nofile: Option<RlimitPair>,
    stack:  Option<RlimitPair>,
    core:   Option<RlimitPair>,
    nproc:  Option<RlimitPair>,
}
