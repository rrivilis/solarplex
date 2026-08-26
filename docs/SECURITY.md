# Security Policy

Solarplex is pre-1.0, actively developed, and has not yet had an independent
external security audit (see the README's "Development Status" section).
The core sandboxing and enforcement path (Guardian, Landlock, seccomp-notify,
the capability DAG) is exactly the kind of code where adversarial review
matters most, and it's explicitly welcome.

## Reporting a vulnerability

**Preferred: [GitHub Private Vulnerability Reporting](https://github.com/rrivilis/solarplex/security/advisories/new)**
(Security tab → "Report a vulnerability"). This opens a private advisory
thread visible only to you and the maintainer with no PGP key exchange or
email to set up or monitor, and it keeps the whole disclosure timeline in
one auditable place.

If you'd rather not use GitHub for the initial report, opening a normal
issue with minimal detail ("I found something, how should I send you the
rest") and asking to move to a private channel is fine too.

**Please don't open a public issue with exploit details or a working PoC.**
Everything else about this project is genuinely open. This is the one
exception, and only until a fix ships.

## What's in scope

Roughly, anything that breaks a trust boundary this project claims to
enforce. See [`docs/threat-model.md`](threat-model.md) for the full
model, including the "Known gaps and future work" section (§11), which
already lists several accepted, non-secret limitations. If what you found
is already listed there, it's still worth confirming you found the same
thing, but chances are that won't be news to me.

Particularly interested in:
- Guardian's sandbox enforcement — Landlock policy gaps, seccomp-notify
  broker logic, anything that lets a sandboxed exec touch a path or syscall
  it wasn't declared for.
- The capability DAG — attenuation bypasses, epoch/revocation races,
  privilege escalation via cap delegation.
- Auth — OIDC flow correctness, session-token handling, anything that lets
  one actor act as another.
- Anything that turns a documented, intentional limitation (§11) into
  something worse than what's already written down about it.

## What's out of scope

- Findings that require local shell access to a box that's already fully
  compromised by some other means (this project doesn't claim to defend
  against that).
- Denial-of-service reports that just describe sending a lot of traffic,
  without a specific amplification or resource-exhaustion bug.
- Anything already tracked in `docs/threat-model.md` §11 as a known,
  accepted gap. Reporting it is fine, but frame it as confirmation, not a
  new finding, and expect that response.
- Social engineering, physical access, or attacks on GitHub/third-party
  infrastructure this project doesn't control.

## What to expect

This is currently maintained by one person, not a security team, so there's
no formal SLA. In good faith: an acknowledgment within a few days, and an
honest read on severity and rough timeline once I've looked at it. Fixes
for anything serious get prioritized over everything else in flight.

## Safe harbor

Good-faith security research that follows this policy (reporting
privately, not exfiltrating more data than needed to demonstrate the issue,
not disrupting availability for other users) won't be met with legal
action from this project. If you're ever unsure whether something you're
about to try crosses a line, ask first.
