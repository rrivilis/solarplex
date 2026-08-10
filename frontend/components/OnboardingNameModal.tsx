"use client";

// ── First-login "name yourself" prompt ───────────────────────────────────────
//
// Trigger condition is deliberately narrow: only when the signed-in actor's
// name still looks like whatever `sub_to_actor_id` fell back to on first
// OIDC login (crates/server/src/auth.rs — `name.or(email).unwrap_or(sub)`),
// not on every visit. A real chosen name (however it was set) never trips
// this again. Reuses the exact same PATCH /auth/me rename path already
// wired into AppNav's user card — this is just a more visible first prompt
// for it, not a new mechanism.

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CurrentActor, getMe, isAuthenticated, updateMyName } from "@/lib/auth";
import { useModalA11y } from "@/hooks/useModalA11y";

const DISMISS_KEY_PREFIX = "sol-onboard-dismissed-";

/**
 * True when `name` looks like it fell through to the OIDC `sub` or `email`
 * claim rather than being an actual chosen display name — the three shapes
 * `sub_to_actor_id` can produce when nothing better was available:
 *   - the email address itself (email claim, no name claim)
 *   - a raw numeric subject id (Google's `sub` is a pure-digit string)
 *   - a ULID (defensive — matches this app's own id shape, in case some
 *     other path ever stashed the actor id itself as the name)
 */
function looksLikeFallbackName(me: CurrentActor): boolean {
  const name = me.name.trim();
  if (!name) return true;
  if (me.email && name === me.email) return true;
  if (/^\d+$/.test(name)) return true;
  if (/^[0-9A-HJKMNP-TV-Z]{26}$/i.test(name)) return true;
  return false;
}

export default function OnboardingNameModal() {
  const queryClient = useQueryClient();

  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    enabled: isAuthenticated(),
    staleTime: 60_000,
  });

  const [dismissed, setDismissed] = useState(true); // safe default pre-hydration
  const [draft, setDraft]         = useState("");
  const [saving, setSaving]       = useState(false);

  // Seed draft + dismissed state once `me` resolves — localStorage is
  // browser-only, so this runs post-hydration, same pattern as the rest of
  // this app's auth-dependent UI (see app/page.tsx).
  useEffect(() => {
    if (!me) return;
    setDismissed(localStorage.getItem(DISMISS_KEY_PREFIX + me.id) === "1");
    setDraft(me.name);
  }, [me]);

  const isOpen = !!me && !dismissed && looksLikeFallbackName(me);

  function dismiss() {
    if (me) localStorage.setItem(DISMISS_KEY_PREFIX + me.id, "1");
    setDismissed(true);
  }

  const modalRef = useModalA11y<HTMLDivElement>(isOpen, dismiss);

  if (!me || !isOpen) return null;

  async function save() {
    const next = draft.trim();
    if (!next) return;
    setSaving(true);
    try {
      await updateMyName(next);
      queryClient.invalidateQueries({ queryKey: ["me"] });
      // Session cards show created_by_name, resolved server-side at fetch
      // time from the actor row this rename just changed — same reason
      // AppNav's inline rename already invalidates this. Without it, a name
      // set here (as opposed to via the sidebar card) leaves the Sessions
      // list showing the pre-rename fallback until something unrelated
      // forces a refetch.
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      dismiss();
    } catch (e) {
      toast.error(`Couldn't save name: ${e instanceof Error ? e.message : "unknown error"}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-[2px] px-4">
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="onboarding-modal-title"
        className="w-full max-w-sm rounded-xl border border-border bg-surface-1 panel-shine p-6 shadow-elevation-modal"
      >
        <h2 id="onboarding-modal-title" className="text-sm font-semibold text-primary mb-1.5">
          What should we call you?
        </h2>
        <p className="text-xs text-muted mb-4 leading-relaxed">
          Your sign-in didn&apos;t include a name, so collaborators currently see{" "}
          <span className="font-mono text-subtle">{me.name}</span>. This is what
          shows up in sessions, chat, and activity — you can change it again
          anytime from the card in the sidebar.
        </p>
        <input
          autoFocus
          value={draft}
          disabled={saving}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Enter") save();
            if (e.key === "Escape") dismiss();
          }}
          placeholder="Your name"
          className="w-full text-sm text-primary bg-surface-2 border border-border rounded-lg px-3 py-2 mb-4 outline-none focus:ring-1 focus:ring-accent-blue/40 focus:border-accent-blue/40"
        />
        <div className="flex items-center justify-end gap-2">
          <button
            onClick={dismiss}
            disabled={saving}
            className="text-xs px-3 py-1.5 rounded-md font-medium text-muted hover:text-subtle hover:bg-surface-2 transition-colors duration-100"
          >
            Skip for now
          </button>
          <button
            onClick={save}
            disabled={saving || !draft.trim()}
            className="text-xs px-4 py-1.5 rounded-md font-medium bg-accent-blue text-surface-0 hover:bg-accent-blue/90 disabled:opacity-50 disabled:hover:bg-accent-blue transition-colors duration-100"
          >
            {saving ? "Saving…" : "Continue"}
          </button>
        </div>
      </div>
    </div>
  );
}
