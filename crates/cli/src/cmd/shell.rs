/// Internal commands used by the fish shell adapter.
/// Hidden from `sp --help` — called via `sp _shell <cmd>`.
use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{client::Client, config::Ctx, output};

#[derive(Args)]
pub struct ShellArgs {
    #[command(subcommand)]
    pub cmd: ShellCmd,
}

#[derive(Subcommand)]
pub enum ShellCmd {
    /// Emit shell.command.started and print the command_id on stdout.
    Start {
        /// Full command string as entered by the user.
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
        /// Opt in to logging the full command argv (default: argv[0] only).
        /// Even with this flag set the credential seatbelt may suppress full
        /// logging if a secret pattern is detected in the command string.
        #[arg(long)]
        tracked: bool,
    },
    /// Emit shell.command.completed.
    Complete {
        /// command_id returned by `start`
        command_id: String,
        #[arg(long)]
        exit: i32,
        #[arg(long)]
        ms: u64,
    },
    /// Emit an OSC-133 semantic markup sequence to stdout.
    /// mark: A=prompt-start B=cmd-start C=pre-exec D=cmd-end
    #[command(name = "osc133")]
    Osc133 {
        mark: char,
        /// Exit code (only used for mark D)
        #[arg(long, default_value = "0")]
        exit: i32,
    },
    /// Set a WezTerm user var (OSC-1337 SetUserVar), base64-encoded.
    #[command(name = "setvar")]
    SetVar { key: String, value: String },
}

pub async fn run(args: ShellArgs, ctx: &Ctx) -> Result<()> {
    match args.cmd {
        ShellCmd::Start { command, tracked } => {
            let client = Client::new(ctx)?;
            start(&client, ctx, &command.join(" "), tracked).await
        }
        ShellCmd::Complete {
            command_id,
            exit,
            ms,
        } => {
            let client = Client::new(ctx)?;
            complete(&client, ctx, &command_id, exit, ms).await
        }
        ShellCmd::Osc133 { mark, exit } => {
            if mark == 'D' {
                output::osc133_exit(exit);
            } else {
                output::osc133(mark);
            }
            Ok(())
        }
        ShellCmd::SetVar { key, value } => {
            output::wezterm_set_var(&key, &value);
            Ok(())
        }
    }
}

async fn start(client: &Client, ctx: &Ctx, command: &str, requested_tracking: bool) -> Result<()> {
    // Silently skip if no session — shell adapter runs in all fish sessions.
    let (session_id, actor_id) = match (ctx.session_id.as_deref(), ctx.actor_id.as_deref()) {
        (Some(s), Some(a)) => (s, a),
        _ => return Ok(()),
    };

    let argv0 = extract_argv0(command);

    // Determine what to emit:
    //
    //   tracked=false              → only argv0; command field absent
    //   tracked=true, seatbelt OK  → full command logged
    //   tracked=true, seatbelt !!  → only argv0; redacted=true; full argv suppressed
    //
    // The seatbelt is defense-in-depth, not the primary security mechanism.
    // The primary defense is that full-command tracking is off by default.
    let (tracked, redacted, logged_command) = if requested_tracking {
        match first_credential_match(command) {
            Some(pattern) => {
                tracing::warn!(
                    argv0 = %argv0,
                    pattern,
                    "shell seatbelt: credential pattern detected, suppressing full command"
                );
                (true, true, None)
            }
            None => (true, false, Some(command.to_string())),
        }
    } else {
        (false, false, None)
    };

    match client
        .shell_start(
            session_id,
            actor_id,
            &argv0,
            logged_command.as_deref(),
            tracked,
            redacted,
        )
        .await
    {
        Ok(id) => print!("{id}"),
        Err(e) => {
            // Non-fatal — shell tracking is best-effort
            tracing::debug!("shell_start: {e}");
        }
    }
    Ok(())
}

async fn complete(
    client: &Client,
    ctx: &Ctx,
    command_id: &str,
    exit_code: i32,
    duration_ms: u64,
) -> Result<()> {
    let (session_id, actor_id) = match (ctx.session_id.as_deref(), ctx.actor_id.as_deref()) {
        (Some(s), Some(a)) => (s, a),
        _ => return Ok(()),
    };
    if command_id.is_empty() {
        return Ok(());
    }
    // Fire-and-forget — ignore error (best-effort telemetry)
    let _ = client
        .shell_complete(session_id, actor_id, command_id, exit_code, duration_ms)
        .await;
    Ok(())
}

// ── Credential seatbelt ───────────────────────────────────────────────────────
//
// These functions are called ONLY when the user has opted in to full-command
// tracking.  The seatbelt is the last line of defence — it catches cases where
// a user opted in globally and then ran a command that accidentally contained a
// raw credential.
//
// Known limitations (documented, not fixable by static analysis):
//
//   VARIABLE REFERENCES: fish_preexec delivers the unexpanded command string.
//     `git push https://$MY_TOKEN@host` → the literal `$MY_TOKEN` appears in
//     argv, not the token value.  This is actually the SAFE pattern — users
//     storing credentials in shell variables keep them out of argv.
//
//   ENCODED SECRETS: `echo c2stYW50LXh4 | base64 -d | xargs curl` — the
//     base64 form does not match any literal pattern.  Users encoding secrets
//     before piping them are following the safe pattern (raw secret never in argv).
//
//   SUB-THRESHOLD FRAGMENTS: if a credential is split across variables or
//     shell arithmetic, each fragment may fall below length thresholds.
//
//   HEREDOC / PROCESS-SUBSTITUTION CONTENT: neither appears in argv at all.
//     These are inherently safe with respect to argv logging.

/// Extract the basename of the first whitespace-delimited token in `command`.
///
/// ```text
/// "/usr/bin/git status"     → "git"
/// "cargo build -p cli"      → "cargo"
/// "./target/debug/sp ls"    → "sp"
/// ""                        → ""
/// ```
pub(crate) fn extract_argv0(command: &str) -> String {
    let first = command.split_whitespace().next().unwrap_or("");
    // Strip any leading path components so we log "git" not "/usr/local/bin/git".
    first.rsplit('/').next().unwrap_or(first).to_string()
}

/// Returns the label of the first credential pattern that matches `command`,
/// or `None` if no known secret pattern is detected.
///
/// Patterns are compiled per-call.  This runs at most once per shell command
/// in a short-lived CLI process — the compile overhead (~µs each) is negligible.
pub(crate) fn first_credential_match(command: &str) -> Option<&'static str> {
    // Each entry: (human-readable label, regex).
    // Labels appear in tracing::warn! and in the stored event — keep them
    // concise and free of PII.
    let patterns: &[(&str, &str)] = &[
        // ── URL-embedded credentials ──────────────────────────────────────────
        // Matches scheme://[user]:password@host.  The username part is optional
        // (`*` not `+`) so bare `:password@` forms (e.g. redis://:pass@host)
        // are also caught.  The password segment must be ≥2 chars so bare
        // `user@host` SSH URLs (no password at all) don't trigger.
        ("url-credential", r"://[^@\s/]*:[^@\s/@]{2,}@"),
        // ── Glued -p<password> (mysql, legacy psql short form) ────────────────
        // Requires ≥8 chars immediately after -p to avoid false-positives on:
        //   -path (find flag, 4 chars)   -prune (5)   -print (5)
        //   -p 3306 (space → no glued match)
        //   -p8080 / -p65535 (port numbers ≤5 digits, < 8-char threshold)
        //   -p8080:8080 (colon not in char class; match breaks at ':' → 4 chars)
        // The `(?:^|\s)` prefix prevents `--password=x` from matching via the
        // `-p` substring embedded inside `--password`.
        ("dash-p-password", r"(?:^|\s)-p[A-Za-z0-9!@#$%^&*_+\-=]{8,}"),
        // ── Explicit credential flags (--password, --token, --secret, …) ──────
        // Covers `--flag=value` and `--flag value` forms.
        // ≥4-char value minimum to skip trivially short args like `--token no`.
        (
            "password-flag",
            r"(?i)--(?:password|passwd|secret|token|api[-_]key|private[-_]key)(?:=|\s)\S{4,}",
        ),
        // ── Authorization header in curl-style -H args ────────────────────────
        // Matches: -H 'Authorization: Bearer <token>'
        //          --header "Authorization: token <value>"
        //          -H 'Authorization: Basic <base64>'
        // Uses `.{8,}` (any chars including spaces) rather than `\S{8,}` because
        // the auth value is typically "TYPE TOKEN" — two whitespace-separated
        // tokens.  Minimum 8 total chars excludes trivial placeholder values.
        ("auth-header", r"(?i)Authorization:\s*.{8,}"),
        // ── Inline env-var assignments where the var name contains a secret key ─
        // Matches: AWS_SECRET_ACCESS_KEY=xxx  GITHUB_TOKEN=xxx  MY_API_KEY=yyy
        // Uppercase-only var name (intentional): standard credential env vars are
        // UPPERCASE; lowercase names like `token_dir=./tokens` are not credentials.
        // ≥4-char value to avoid empty/trivial assignments.
        (
            "env-credential",
            r"\b(?:[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|AUTH)[A-Z0-9_]*)=\S{4,}",
        ),
        // ── Known literal token prefixes ──────────────────────────────────────
        // Caught regardless of context — a raw token pasted anywhere in argv.
        //
        // GitHub personal (ghp_), server-to-server (ghs_), OAuth (gho_), refresh (ghr_)
        ("github-token", r"gh[psor]_[A-Za-z0-9]{10,}"),
        // Anthropic API key
        ("anthropic-key", r"sk-ant-[A-Za-z0-9\-_]{20,}"),
        // OpenAI / generic sk- key — pure alphanumeric ≥24 chars after sk-.
        // Hyphens excluded so sk-ant-* (checked above) doesn't also trigger here.
        ("openai-key", r"sk-[A-Za-z0-9]{24,}"),
        // AWS Access Key ID — always AKIA + exactly 16 uppercase alphanumeric chars.
        ("aws-access-key", r"AKIA[A-Z0-9]{16}"),
    ];

    for &(label, pattern) in patterns {
        // All patterns are validated by `all_patterns_compile` test.
        let re = regex::Regex::new(pattern).expect("invalid built-in seatbelt pattern");
        if re.is_match(command) {
            return Some(label);
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── extract_argv0 ────────────────────────────────────────────────────────

    #[test]
    fn argv0_simple() {
        assert_eq!(extract_argv0("git commit -m 'msg'"), "git");
    }

    #[test]
    fn argv0_absolute_path_stripped() {
        assert_eq!(extract_argv0("/usr/bin/git status"), "git");
    }

    #[test]
    fn argv0_relative_path_stripped() {
        assert_eq!(extract_argv0("./target/debug/sp session ls"), "sp");
    }

    #[test]
    fn argv0_empty() {
        assert_eq!(extract_argv0(""), "");
    }

    #[test]
    fn argv0_whitespace_only() {
        assert_eq!(extract_argv0("   "), "");
    }

    #[test]
    fn argv0_no_args() {
        assert_eq!(extract_argv0("cargo"), "cargo");
    }

    // ─── Seatbelt: must detect ────────────────────────────────────────────────

    #[test]
    fn detects_url_credential_git_https() {
        let cmd = "git clone https://alice:ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@github.com/org/repo";
        assert_eq!(first_credential_match(cmd), Some("url-credential"));
    }

    #[test]
    fn detects_url_credential_psql() {
        let cmd = "psql postgresql://alice:s3cr3tP4ssw0rd@db.prod.example.com/mydb";
        assert_eq!(first_credential_match(cmd), Some("url-credential"));
    }

    #[test]
    fn detects_url_credential_redis() {
        // Redis URL with bare :password@ (no username)
        let cmd = "redis-cli -u redis://:mypassword@cache.example.com:6379";
        assert_eq!(first_credential_match(cmd), Some("url-credential"));
    }

    #[test]
    fn detects_url_credential_mongo() {
        let cmd = "mongosh mongodb://admin:hunter2@mongo.internal:27017/mydb";
        assert_eq!(first_credential_match(cmd), Some("url-credential"));
    }

    #[test]
    fn detects_mysql_glued_password() {
        // -p immediately followed by password — classic MySQL short form, 8+ chars
        let cmd = "mysql -u root -pMyP@ssw0rd! -h localhost mydb";
        assert_eq!(first_credential_match(cmd), Some("dash-p-password"));
    }

    #[test]
    fn detects_mysql_glued_password_alphanumeric() {
        let cmd = "mysqldump -ppassword123 mydb > dump.sql";
        assert_eq!(first_credential_match(cmd), Some("dash-p-password"));
    }

    #[test]
    fn detects_password_equals_flag() {
        let cmd = "some-tool --password=hunter2 --user=admin";
        assert_eq!(first_credential_match(cmd), Some("password-flag"));
    }

    #[test]
    fn detects_token_space_flag() {
        let cmd = "some-tool --token abcdef1234";
        assert_eq!(first_credential_match(cmd), Some("password-flag"));
    }

    #[test]
    fn detects_secret_flag() {
        let cmd = "vault login --secret mysecretvalue";
        assert_eq!(first_credential_match(cmd), Some("password-flag"));
    }

    #[test]
    fn detects_api_key_flag() {
        let cmd = "cli --api-key XXXXXXXXXXXXXXXX";
        assert_eq!(first_credential_match(cmd), Some("password-flag"));
    }

    #[test]
    fn detects_authorization_bearer() {
        let cmd = "curl -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9' https://api.example.com";
        assert_eq!(first_credential_match(cmd), Some("auth-header"));
    }

    #[test]
    fn detects_authorization_basic() {
        let cmd = "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' https://api.example.com";
        assert_eq!(first_credential_match(cmd), Some("auth-header"));
    }

    #[test]
    fn detects_github_token_in_header() {
        // github-token pattern fires (before auth-header in the list)
        let cmd = r#"curl --header "Authorization: token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx" https://api.github.com"#;
        assert!(first_credential_match(cmd).is_some());
    }

    #[test]
    fn detects_github_personal_token_bare() {
        // Token pasted directly into command (echo | gh auth)
        let cmd = "echo ghp_xxxxxxxxxxxxxxxxxxxx | gh auth login --with-token";
        assert_eq!(first_credential_match(cmd), Some("github-token"));
    }

    #[test]
    fn detects_github_server_token() {
        let cmd = "curl -H 'Authorization: Bearer ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'";
        assert!(first_credential_match(cmd).is_some());
    }

    #[test]
    fn detects_anthropic_key_in_header() {
        let cmd = "curl https://api.anthropic.com/v1/messages -H 'x-api-key: sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'";
        assert_eq!(first_credential_match(cmd), Some("anthropic-key"));
    }

    #[test]
    fn detects_aws_access_key_id() {
        let cmd = "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE";
        assert_eq!(first_credential_match(cmd), Some("aws-access-key"));
    }

    #[test]
    fn detects_aws_secret_env_inline() {
        let cmd = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY aws s3 sync";
        assert_eq!(first_credential_match(cmd), Some("env-credential"));
    }

    #[test]
    fn detects_github_token_env_inline() {
        // GITHUB_TOKEN contains the keyword TOKEN
        let cmd = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx gh pr list";
        assert_eq!(first_credential_match(cmd), Some("env-credential"));
    }

    #[test]
    fn detects_anthropic_api_key_env_inline() {
        // ANTHROPIC_API_KEY contains API_KEY keyword
        let cmd = "ANTHROPIC_API_KEY=sk-ant-xxx python train.py";
        assert_eq!(first_credential_match(cmd), Some("env-credential"));
    }

    #[test]
    fn detects_db_password_env_inline() {
        let cmd = "DB_PASSWORD=s3cr3t rails db:migrate";
        assert_eq!(first_credential_match(cmd), Some("env-credential"));
    }

    #[test]
    fn detects_export_secret() {
        let cmd = "export MY_SECRET=xxxxxxxxxx";
        assert_eq!(first_credential_match(cmd), Some("env-credential"));
    }

    // ─── Adversarial bypass attempts ──────────────────────────────────────────

    #[test]
    fn adversarial_variable_reference_in_url() {
        // fish_preexec delivers the UNEXPANDED command string.
        // `$MY_TOKEN` is literally those 9 chars — the URL pattern requires
        // `://[chars]:[chars]@`; the `$MY_TOKEN` segment contains no `:` so
        // the `user:pass@` structure doesn't form.
        // This is the SAFE pattern: variable indirection keeps the raw credential
        // out of argv.  Documented: seatbelt cannot expand shell variables.
        let cmd = "git push https://$MY_TOKEN@github.com/org/repo";
        assert!(
            first_credential_match(cmd).is_none(),
            "variable reference is the safe pattern — must not trigger seatbelt"
        );
    }

    #[test]
    fn adversarial_ssh_url_bypasses_url_pattern() {
        // SSH git URLs have no password segment
        let cmd = "git clone git@github.com:org/repo.git";
        assert!(first_credential_match(cmd).is_none());
    }

    #[test]
    fn adversarial_echo_pipe_raw_token_still_caught() {
        // Attacker tries to obscure by piping through echo, but the raw token
        // literal still appears in argv and is caught by github-token.
        let cmd = "echo ghp_xxxxxxxxxxxxxxxxxxxx | gh auth login --with-token";
        assert_eq!(
            first_credential_match(cmd),
            Some("github-token"),
            "raw token in echo arg must be caught even when piped"
        );
    }

    #[test]
    fn adversarial_base64_encoded_token_not_caught() {
        // The base64-encoded form does not match any literal pattern.
        // Documented limitation: encoding defeats static matching.
        // Mitigation: if the user is encoding then decoding, the plaintext
        // never appears raw in argv — they are following the safe pattern.
        let cmd = "echo c2stYW50LWFwaTAzLVhYWFhYWFhYWA== | base64 -d | xargs curl";
        assert!(
            first_credential_match(cmd).is_none(),
            "base64-encoded token: documented limitation — not caught by seatbelt"
        );
    }

    #[test]
    fn adversarial_heredoc_is_argv_safe() {
        // Password delivered via heredoc appears in stdin, not argv.
        let cmd = "psql -h localhost -U admin mydb << 'EOF'";
        assert!(
            first_credential_match(cmd).is_none(),
            "heredoc body is stdin, not argv — inherently safe"
        );
    }

    #[test]
    fn adversarial_process_substitution_is_argv_safe() {
        // Process substitution: the file descriptor reference appears in argv,
        // not the file contents.
        let cmd = "some-tool --key-file <(cat ~/.config/api_key)";
        assert!(
            first_credential_match(cmd).is_none(),
            "process substitution: fd in argv, not secret content"
        );
    }

    #[test]
    fn adversarial_url_without_scheme_separator() {
        // Attacker omits `://` to bypass URL pattern.
        // The URL pattern anchors on `://`; without it, no match.
        // Mitigation: the shell/tool would also fail to parse such a URL.
        let cmd = "git clone user:password@github.com/org/repo.git";
        // No `://` → no url-credential match.
        // `user:password` might look like it triggers something but none of
        // our other patterns apply here without more context.
        let result = first_credential_match(cmd);
        // Document: this specific bypass MAY or MAY NOT be caught depending on
        // other patterns.  We assert only that we don't panic.
        let _ = result;
    }

    #[test]
    fn adversarial_short_openai_key_below_threshold() {
        // openai-key requires 24+ chars after sk-; short tokens don't match.
        // Real OpenAI keys are always ≥48 chars, so this only matters for
        // adversarially crafted short strings.
        let cmd = "curl --key sk-shortXXXXXXX"; // 11 chars after sk-, < 24
        assert!(first_credential_match(cmd).is_none());
    }

    #[test]
    fn adversarial_lowercase_env_var_not_caught() {
        // Lowercase env var names are NOT credential vars by convention.
        // This is an intentional design decision to prevent false positives.
        let cmd = "token_dir=./tokens run_script.sh";
        assert!(
            first_credential_match(cmd).is_none(),
            "lowercase env var must not trigger — standard credential vars are UPPERCASE"
        );
    }

    // ─── Seatbelt: must NOT trigger (false-positive prevention) ──────────────

    #[test]
    fn safe_git_push() {
        assert!(first_credential_match("git push origin main").is_none());
    }

    #[test]
    fn safe_cargo_build() {
        assert!(first_credential_match("cargo build -p cli").is_none());
    }

    #[test]
    fn safe_psql_prompt_flag() {
        // -W means "prompt for password" — no credential in argv
        assert!(first_credential_match("psql -h localhost -U alice -W mydb").is_none());
    }

    #[test]
    fn safe_psql_user_only_url() {
        // user@host without :password@
        assert!(first_credential_match("psql postgresql://alice@localhost/mydb").is_none());
    }

    #[test]
    fn safe_mysql_port_spaced() {
        // Space between -p and port number — not a glued match
        assert!(first_credential_match("mysql -p 3306 -u root localhost").is_none());
    }

    #[test]
    fn safe_mysql_port_glued_4digit() {
        // -p3306: 4 digits after -p, below 8-char threshold
        assert!(first_credential_match("mysql -p3306 -u root").is_none());
    }

    #[test]
    fn safe_mysql_port_glued_max() {
        // -p65535: 5 digits (max valid port), below threshold
        assert!(first_credential_match("mysql -p65535 -u root").is_none());
    }

    #[test]
    fn safe_find_path_flag() {
        // -path: 4 chars after -p, below 8-char threshold
        assert!(first_credential_match("find . -path '*/node_modules' -prune -o -print").is_none());
    }

    #[test]
    fn safe_find_prune() {
        // -prune: 5 chars, below threshold
        assert!(first_credential_match("find /var -prune").is_none());
    }

    #[test]
    fn safe_docker_publish_spaced() {
        assert!(first_credential_match("docker run -p 8080:8080 myimage").is_none());
    }

    #[test]
    fn safe_docker_publish_glued() {
        // -p8080:8080: colon breaks the match before reaching 8 chars
        assert!(first_credential_match("docker run -p8080:8080 myimage").is_none());
    }

    #[test]
    fn safe_ssh_url() {
        assert!(first_credential_match("ssh git@github.com").is_none());
    }

    #[test]
    fn safe_curl_no_auth() {
        assert!(first_credential_match("curl https://api.example.com/health").is_none());
    }

    #[test]
    fn safe_rm_rf() {
        // Dangerous but not a credential leak
        assert!(first_credential_match("rm -rf /tmp/build").is_none());
    }

    #[test]
    fn safe_k8s_apply() {
        assert!(first_credential_match("kubectl apply -f deployment.yaml").is_none());
    }

    #[test]
    fn safe_short_token_flag_value() {
        // --token with a 3-char value: below the 4-char minimum
        assert!(first_credential_match("tool --token abc").is_none());
    }

    #[test]
    fn safe_unrelated_uppercase_env_var() {
        // Uppercase env var whose name contains no credential keyword
        assert!(first_credential_match("SOLARPLEX_GATE_PATTERNS='rm -rf' sp session ls").is_none());
    }

    #[test]
    fn safe_openai_key_prefix_only() {
        // "sk-" prefix but only a few chars — below 24-char threshold
        assert!(first_credential_match("sk-tooShort").is_none());
    }

    // ─── Pattern validity ─────────────────────────────────────────────────────

    #[test]
    fn all_patterns_compile() {
        // Runs first_credential_match on a harmless string, which exercises every
        // Regex::new() call.  Any invalid pattern would panic here.
        first_credential_match("harmless command string with no credentials");
    }
}
