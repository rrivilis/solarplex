use std::io::IsTerminal as _;

use protocol::types::EntityHandle;

/// Returns true when stdout is an interactive terminal (OSC-8 / colors safe).
pub fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

// ── OSC-8 hyperlinks ──────────────────────────────────────────────────────────

/// Wrap `text` in an OSC-8 hyperlink pointing at `uri`.
/// Falls back to plain text when stdout is not a terminal.
///
/// Callers must use `solarplex://...` (with the authority slashes), not bare
/// `solarplex:...` — Windows Terminal resolves clicked hyperlinks via WinRT's
/// `Windows.Foundation.Uri`/`Launcher.LaunchUriAsync`, which (unlike `mailto:`
/// and a handful of other specially-registered schemes) requires an
/// authority marker for unrecognized custom schemes to parse at all. Without
/// it, the click silently does nothing — no error, the link just never fires.
pub fn link(uri: &str, text: &str) -> String {
    if is_tty() {
        format!("\x1b]8;;{uri}\x1b\\{text}\x1b]8;;\x1b\\")
    } else {
        text.to_string()
    }
}

/// Format a Solarplex entity reference as a clickable OSC-8 hyperlink.
///
/// The URI uses the canonical `solarplex://entity/id` scheme so that:
///   - WezTerm's `open-uri` handler routes it through `sp plumb` directly —
///     no OS involvement, this is the only path that doesn't need `sp
///     _install_uri_handler` run first
///   - Elsewhere, `sp _install_uri_handler` registers the OS-level handoff:
///     xdg-mime on Linux, the `HKCU\Software\Classes\solarplex` registry key
///     on Windows (see plumb.rs::install_uri_handler for both) — required
///     for a click to go anywhere outside WezTerm
///   - No running frontend is required for basic navigation
///
/// `entity` — "artifact" | "approval" | "session" | "cap" | "actor"
/// `id`     — full ULID or short name (e.g. "alice" for actor)
/// `session_id` — unused now but kept for call-site compatibility
/// `_ui`    — retained for signature compatibility; ignored
pub fn entity_link(entity: &str, id: &str, _session_id: &str, _ui: &str) -> String {
    let short = short_id(id);
    let label = format!("{entity}/{short}");
    let uri = format!("solarplex://{entity}/{id}");
    link(&uri, &label)
}

/// Like `entity_link` but accepts a typed `EntityHandle`.
/// Prefer this at new call sites — eliminates the raw entity-type string and
/// prevents entity/id mismatches.
#[allow(dead_code)]
pub fn handle_link(handle: &EntityHandle, session_id: &str, ui: &str) -> String {
    entity_link(handle.entity_type(), handle.id(), session_id, ui)
}

/// Like `entity_link` but omits the entity prefix in the label — useful when
/// the entity type is already clear from context (e.g. inside an artifact table).
#[allow(dead_code)]
pub fn id_link(entity: &str, id: &str) -> String {
    let uri = format!("solarplex://{entity}/{id}");
    link(&uri, short_id(id))
}

/// Render a chain of parent entity refs as a backtrack navigation bar.
///
/// Displayed at the top of every entity view so you always know your position
/// in the object graph and can click back to any ancestor.
///
/// `crumbs` — `(kind, id, display_name)` tuples, outermost parent first:
///   - `id = ""` → collection link (renders as `kind/`)
///   - `display_name = ""` → falls back to `short_id(id)`
///
/// # Examples
/// ```text
/// backtrace_links(&[("sessions","","")])
/// // ← sessions/
///
/// backtrace_links(&[("sessions","",""), ("session","01J8X","PaymentsAlloc")])
/// // ← sessions/  ←  session/PaymentsAlloc
///
/// backtrace_links(&[("session","01J8X",""), ("actor","alice","alice")])
/// // ← session/01J8X  ←  actor/alice
/// ```
pub fn backtrace_links(crumbs: &[(&str, &str, &str)]) -> String {
    if crumbs.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = crumbs
        .iter()
        .map(|(kind, id, name)| {
            if id.is_empty() {
                // Collection ref — links to `sp ask <kind>/`
                let uri = format!("solarplex://ask/{kind}");
                link(&uri, &format!("{kind}/"))
            } else {
                let label = if !name.is_empty() {
                    format!("{kind}/{name}")
                } else {
                    format!("{kind}/{}", short_id(id))
                };
                let uri = format!("solarplex://{kind}/{id}");
                link(&uri, &label)
            }
        })
        .collect();
    dim(&format!("←  {}", parts.join("  ←  ")))
}

/// Clickable action link: `solarplex://entity/id/action` with a short label.
/// e.g. link_action("session", "01J...", "enter", "enter")
pub fn link_action(entity: &str, id: &str, action: &str, label: &str) -> String {
    let uri = format!("solarplex://{entity}/{id}/{action}");
    link(&uri, label)
}

/// Clickable actor reference. Label is "actor/id" so it's visually consistent
/// with other entity refs and recognisably clickable.
pub fn actor_link(id: &str) -> String {
    let uri = format!("solarplex://actor/{id}");
    link(&uri, &format!("actor/{id}"))
}

/// Like `actor_link`, but labelled with a resolved display name when one's
/// available — falls back to the plain id-labelled form otherwise (name
/// empty, or happens to equal the id). `SessionMember.name` is resolved
/// server-side and should basically always be populated by the time a
/// snapshot reaches a client (see that struct's own doc comment), but this
/// stays defensive rather than assuming.
pub fn actor_link_named(id: &str, name: &str) -> String {
    if name.is_empty() || name == id {
        return actor_link(id);
    }
    let uri = format!("solarplex://actor/{id}");
    link(&uri, name)
}

/// Return the first 8 chars (4-char block) of a ULID for compact display.
pub fn short_id(id: &str) -> &str {
    if id.len() > 8 {
        &id[..8]
    } else {
        id
    }
}

// ── ANSI colour helpers ───────────────────────────────────────────────────────

pub fn green(s: &str) -> String {
    colour(s, "32")
}
pub fn red(s: &str) -> String {
    colour(s, "31")
}
pub fn yellow(s: &str) -> String {
    colour(s, "33")
}
pub fn cyan(s: &str) -> String {
    colour(s, "36")
}
pub fn dim(s: &str) -> String {
    colour(s, "2")
}
pub fn bold(s: &str) -> String {
    colour(s, "1")
}

fn colour(s: &str, code: &str) -> String {
    if is_tty() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

// ── Table ─────────────────────────────────────────────────────────────────────

/// Left-pad `s` to at least `width` display characters.
pub fn pad(s: &str, width: usize) -> String {
    // Strip ANSI escapes for width calculation.
    let visible_len = strip_ansi(s).len();
    if visible_len >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - visible_len))
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c == 'm' || c == '\\' {
                in_escape = false;
            }
            continue;
        }
        out.push(c);
    }
    out
}

// ── OSC-133 semantic markup (Option A) ───────────────────────────────────────
//
// WezTerm and Rio both support OSC-133 "shell integration" sequences.
// They mark the prompt/command/output regions so the terminal understands
// where commands start and stop.  Reference:
//   https://wezfurlong.org/wezterm/shell-integration.html
//   OSC 133 ; A  — prompt start
//   OSC 133 ; B  — command start (after prompt, before user input)
//   OSC 133 ; C  — pre-execution (after user hits Enter)
//   OSC 133 ; D ; <exit>  — command finished
//
// We emit these in the shell adapter so the terminal knows about every
// shell command tracked by the session.  The fish plugin calls
// `sp _osc133 <mark>` (below) rather than embedding raw escapes in fish,
// so the sequences come through the subprocess's stdout, which WezTerm
// passes through correctly.

/// Emit a raw OSC-133 mark to stdout.  No-op when not a tty.
pub fn osc133(mark: char) {
    if is_tty() {
        // OSC = ESC ]   ST = ESC \
        print!("\x1b]133;{mark}\x1b\\");
    }
}

/// Emit OSC-133 D (command finished) with an exit code.
pub fn osc133_exit(code: i32) {
    if is_tty() {
        print!("\x1b]133;D;{code}\x1b\\");
    }
}

/// Emit a WezTerm OSC-1337 "SetUserVar" to stash the current Solarplex
/// session ID inside the terminal pane.  WezTerm exposes this via
/// `wezterm.mux.get_tab()` etc., so a WezTerm plugin can read it without
/// any extra IPC.
pub fn wezterm_set_var(key: &str, val: &str) {
    if is_tty() {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(val);
        print!("\x1b]1337;SetUserVar={key}={encoded}\x07");
    }
}

// ── Terminal sanitization ─────────────────────────────────────────────────────

/// Strip terminal control sequences from foreign-authored content before printing.
///
/// Must be called on every string that originated from an event payload, artifact
/// content, context entry, actor-supplied name, or any other data authored by a
/// session participant before it reaches println!/print!.
///
/// Removes:
///   CSI sequences  (\x1b[ … final-byte)  — ANSI colors, cursor movement, etc.
///   OSC sequences  (\x1b] … BEL | ST)    — OSC-8 links, OSC-52 clipboard write,
///                                           OSC-7 working-directory spoof, etc.
///   Other ESC      (\x1b + one byte)      — remaining two-byte escape forms
///   C0 controls    (\x00–\x1f)            — except HT (\t), LF (\n), CR (\r)
///   DEL            (\x7f)
///   C1 controls    (U+0080–U+009F)        — covers 8-bit OSC/CSI entry points
pub fn sanitize_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                match chars.peek().copied() {
                    Some('[') => {
                        // CSI: ESC [ <param/intermediate bytes> <final byte 0x40–0x7e>
                        chars.next();
                        loop {
                            match chars.peek().copied() {
                                Some(c) if ('\x20'..='\x3f').contains(&c) => {
                                    chars.next();
                                }
                                Some(c) if ('\x40'..='\x7e').contains(&c) => {
                                    chars.next();
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }
                    Some(']') => {
                        // OSC: ESC ] … BEL (\x07) or ST (ESC \)
                        chars.next();
                        loop {
                            match chars.next() {
                                Some('\x07') | None => break,
                                Some('\x1b') => {
                                    chars.next();
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(_) => {
                        chars.next();
                    } // other two-byte ESC sequences
                    None => {}
                }
            }
            // C0 — allow HT, LF, CR only
            '\x00'..='\x08' | '\x0b'..='\x0c' | '\x0e'..='\x1f' | '\x7f' => {}
            // C1 (U+0080–U+009F)
            c if ('\u{0080}'..='\u{009f}').contains(&c) => {}
            c => out.push(c),
        }
    }
    out
}

// ── Status symbols ────────────────────────────────────────────────────────────

pub fn status_icon(status: &str) -> &'static str {
    match status {
        "active" => "●",
        "archived" => "○",
        "suspended" => "◐",
        "granted" => "✓",
        "denied" => "✗",
        "pending" => "⋯",
        "running" => "▶",
        "waiting" => "⏳",
        "idle" => "·",
        "error" => "✕",
        _ => "?",
    }
}
