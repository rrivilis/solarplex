"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { authFetch, isAuthenticated, signIn, getSpToken } from "@/lib/auth";
import { API_BASE } from "@/lib/env";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import LoadingSpinner from "@/components/LoadingSpinner";

interface InvitePreview {
  id: string;
  session_id: string;
  session_name: string;
  invited_by: string;
  inviter_name: string;
  role: string;
  invitee_email: string | null;
  expires_at: string;
  redeemed_at: string | null;
  revoked_at: string | null;
}

const ROLE_LABEL: Record<string, string> = {
  owner: "Owner",
  collaborator: "Collaborator",
  observer: "Observer",
};

export default function InvitePage() {
  const params = useParams();
  const router = useRouter();
  const inviteId = params.id as string;

  const [preview, setPreview]       = useState<InvitePreview | null>(null);
  const [loading, setLoading]       = useState(true);
  const [loadError, setLoadError]   = useState<string | null>(null);
  const [redeeming, setRedeeming]   = useState(false);
  const [redeemError, setRedeemError] = useState<string | null>(null);

  // Never the raw invite/session ID — a session name once the preview
  // loads, a neutral placeholder before that or on failure.
  useDocumentTitle(preview ? `Invite: ${preview.session_name}` : loadError ? "Invite not found" : "Invite");

  useEffect(() => {
    let cancelled = false;
    // Deliberately unauthenticated — see routes::invites::preview. Someone
    // seeing this page hasn't joined the session yet, so there's nothing to
    // gate; the server merges in session_name for exactly this case.
    fetch(`${API_BASE}/invites/${inviteId}`)
      .then(async r => {
        if (!r.ok) throw new Error(r.status === 404 ? "Invite not found" : `HTTP ${r.status}`);
        return r.json() as Promise<InvitePreview>;
      })
      .then(data => { if (!cancelled) setPreview(data); })
      .catch(e => { if (!cancelled) setLoadError(e instanceof Error ? e.message : "Failed to load invite"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [inviteId]);

  async function handleAccept() {
    const token = getSpToken();
    if (!token) {
      // Shouldn't happen — the accept button only renders when authenticated
      // — but redirect through sign-in rather than send a malformed request.
      signIn(`/invite/${inviteId}`);
      return;
    }
    setRedeeming(true);
    setRedeemError(null);
    try {
      const res = await authFetch(`${API_BASE}/invites/${inviteId}/redeem`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sp_token: token }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      const data = await res.json();
      router.push(`/sessions/${data.session_id}`);
    } catch (e) {
      setRedeemError(e instanceof Error ? e.message : "Failed to accept invite");
      setRedeeming(false);
    }
  }

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0">
        <LoadingSpinner size={40} />
      </div>
    );
  }

  if (loadError || !preview) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Invite not found</h1>
          <p className="text-xs text-muted mb-6">{loadError ?? "This invite link is invalid."}</p>
          <Link href="/" className="text-xs text-accent-blue hover:underline">← Back to Solarplex</Link>
        </div>
      </div>
    );
  }

  const expired  = new Date(preview.expires_at) <= new Date();
  const revoked  = preview.revoked_at !== null;
  const redeemed = preview.redeemed_at !== null;

  return (
    <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
      <div className="w-[380px] rounded-xl border border-border bg-surface-1 panel-shine p-6 text-center">
        <div className="text-3xl mb-4 text-accent-blue select-none leading-none">⬡</div>
        <h1 className="text-sm font-semibold text-primary mb-1">You&apos;ve been invited to</h1>
        <p className="text-base font-semibold text-accent-blue mb-4">{preview.session_name}</p>
        <p className="text-xs text-muted mb-6">
          as <span className="text-subtle font-medium">{ROLE_LABEL[preview.role] ?? preview.role}</span>
          {" · invited by "}
          <span className="text-subtle font-medium">{preview.inviter_name}</span>
        </p>

        {revoked ? (
          <>
            <p className="text-xs text-accent-red mb-4">This invite has been revoked.</p>
            <Link
              href="/"
              className="block w-full py-2 rounded-lg font-medium bg-surface-2 hover:bg-surface-3 text-subtle text-xs transition-colors"
            >
              ← Back to Solarplex
            </Link>
          </>
        ) : redeemed ? (
          <>
            <p className="text-xs text-muted mb-4">This invite has already been redeemed.</p>
            {/* Reachable again from the Inbox after the fact (e.g. clicking
                an old invite entry there) — without this there was no way
                back except the browser's own Back button, which isn't
                reliable when the invite was opened in a new tab. */}
            <Link
              href={`/sessions/${preview.session_id}`}
              className="block w-full py-2 rounded-lg font-semibold bg-accent-blue text-surface-0 hover:bg-accent-blue/90 text-xs transition-colors"
            >
              Return to session →
            </Link>
          </>
        ) : expired ? (
          <>
            <p className="text-xs text-accent-red mb-4">This invite has expired.</p>
            <Link
              href="/"
              className="block w-full py-2 rounded-lg font-medium bg-surface-2 hover:bg-surface-3 text-subtle text-xs transition-colors"
            >
              ← Back to Solarplex
            </Link>
          </>
        ) : (
          <>
            {redeemError && (
              <div className="text-xs text-accent-red bg-accent-red/10 border border-accent-red/20 rounded-lg px-3 py-2 mb-4">
                {redeemError}
              </div>
            )}
            {isAuthenticated() ? (
              <button
                onClick={handleAccept}
                disabled={redeeming}
                className="w-full py-2 rounded-lg bg-accent-blue text-surface-0 text-xs font-semibold hover:bg-accent-blue/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {redeeming ? "Joining…" : "Accept invite"}
              </button>
            ) : (
              <button
                onClick={() => signIn(`/invite/${inviteId}`)}
                className="w-full py-2 rounded-lg bg-accent-blue text-surface-0 text-xs font-semibold hover:bg-accent-blue/90 transition-colors"
              >
                Sign in to accept
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}
