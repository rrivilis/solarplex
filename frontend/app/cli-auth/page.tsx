"use client";

// ── CLI login handoff ────────────────────────────────────────────────────────
//
// `sp login` opens this page (with ?port=<ephemeral local port>&nonce=<random>)
// instead of hitting /auth/oidc/start directly, so the *existing*,
// already-reviewed OIDC flow (PKCE, nonce, is_safe_return_to) runs completely
// unmodified — this page only adds the last mile: handing the sp_token this
// browser already has to the CLI process waiting on 127.0.0.1:<port>. No
// server-side change was needed for this at all.
//
// Validity, not just presence: this page confirms the token actually still
// works (via GET /auth/me) rather than trusting `isAuthenticated()`'s local
// "is something in localStorage" check. A stale/revoked cached token is
// still "present" — handing that off would make `sp login` report success
// and then fail on the very next command with a confusing error, which is
// exactly what a shallow presence check produced in practice.
//
// The handoff request uses `mode: "no-cors"` deliberately: this page has no
// need to read the response (the CLI writes its own success page), and
// no-cors sidesteps needing CORS headers on a listener whose whole purpose
// is to close itself after exactly one request. `nonce` is echoed back on
// that request so the CLI's listener only accepts a callback from the exact
// tab it opened — see crates/cli/src/cmd/login.rs for the other half.

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { captureSpTokenFromHash, getMe, getSpToken, signIn } from "@/lib/auth";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

type Phase = "checking" | "redirecting" | "handing-off" | "done" | "error";

function CliAuthInner() {
  useDocumentTitle("CLI Sign-in");
  const searchParams = useSearchParams();
  const port  = searchParams.get("port");
  const nonce = searchParams.get("nonce");

  const [phase, setPhase] = useState<Phase>("checking");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    captureSpTokenFromHash();

    if (!port || !/^\d+$/.test(port) || !nonce) {
      setPhase("error");
      setError("Missing or invalid ?port=/?nonce= — open this page via `sp login`, not directly.");
      return;
    }

    getMe().then(me => {
      if (cancelled) return;

      if (!me) {
        // No token, or the one we have doesn't actually validate anymore
        // (expired/revoked) — either way, this is not "signed in enough to
        // hand off." Force a real OIDC round-trip rather than looping.
        setPhase("redirecting");
        signIn(`/cli-auth?port=${port}&nonce=${nonce}`);
        return;
      }

      const token = getSpToken();
      if (!token) {
        setPhase("error");
        setError("Signed in, but no token was found. Try `sp login` again.");
        return;
      }

      setPhase("handing-off");
      fetch(`http://127.0.0.1:${port}/callback?token=${encodeURIComponent(token)}&nonce=${encodeURIComponent(nonce)}`, {
        mode: "no-cors",
      })
        .catch(() => {
          // no-cors responses are opaque either way — a network-level failure
          // (CLI process gone, port closed) is the only thing that lands here.
        })
        .finally(() => { if (!cancelled) setPhase("done"); });
    });

    return () => { cancelled = true; };
  }, [port, nonce]);

  return (
    <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
      <div className="w-[380px] rounded-xl border border-border bg-surface-1 panel-shine p-6 text-center">
        <div className="text-3xl mb-4 text-accent-blue select-none leading-none">⬡</div>
        <h1 className="text-sm font-semibold text-primary mb-2">Solarplex CLI sign-in</h1>

        {phase === "error" ? (
          <p className="text-xs text-accent-red">{error}</p>
        ) : phase === "redirecting" ? (
          <p className="text-xs text-muted">Redirecting to sign in…</p>
        ) : phase === "done" ? (
          <>
            <p className="text-xs text-subtle mb-1">You&apos;re signed in.</p>
            <p className="text-xs text-muted">Return to your terminal — `sp login` should confirm in a moment.</p>
          </>
        ) : (
          <p className="text-xs text-muted">Completing sign-in…</p>
        )}
      </div>
    </div>
  );
}

export default function CliAuthPage() {
  return (
    <Suspense fallback={<div className="flex h-full bg-surface-0" />}>
      <CliAuthInner />
    </Suspense>
  );
}
