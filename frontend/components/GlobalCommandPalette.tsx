"use client";

import { usePathname } from "next/navigation";
import CommandPalette from "@/components/CommandPalette";

/**
 * Mounts the command palette at the root layout level so ⌘K works on every
 * page, not just inside a session.
 *
 * On session pages (/sessions/:id) the palette surfaces tab-switching and
 * transfer actions.  Those are bridged via custom DOM events since the palette
 * lives outside the session page's component tree.
 *
 * Session page listens for:
 *   window.addEventListener("sol:switch-tab", (e) => setTab(e.detail))
 *
 * A parsed command (crates/intent, via lib/intent.ts) reuses the same
 * event-bridge pattern — one more custom event per destination surface,
 * dispatched with no payload beyond an optional detail the session page
 * uses to pre-fill a field (e.g. invite role). Selecting a parsed command
 * never calls a mutating endpoint itself; it only opens the surface where
 * the user takes the real, already-authorized action.
 */
export default function GlobalCommandPalette() {
  const pathname = usePathname();

  // Extract session ID from /sessions/:id (or /sessions/:id/...)
  const match = pathname?.match(/^\/sessions\/([^/]+)/);
  const sessionId = match?.[1] ?? undefined;

  function onSwitchTab(tab: string) {
    window.dispatchEvent(new CustomEvent("sol:switch-tab", { detail: tab }));
  }

  function onTransfer() {
    window.dispatchEvent(new CustomEvent("sol:open-transfer"));
  }

  function onOpenManage() {
    window.dispatchEvent(new CustomEvent("sol:open-manage"));
  }

  function onOpenNeedsAction() {
    window.dispatchEvent(new CustomEvent("sol:open-needs-action"));
  }

  function onOpenInvite(role?: string, email?: string, ttlSecs?: number) {
    window.dispatchEvent(new CustomEvent("sol:open-invite", { detail: { role, email, ttlSecs } }));
  }

  function onNewSession() {
    window.dispatchEvent(new CustomEvent("sol:open-new-session"));
  }

  function onOpenAttach(name?: string, ttlSecs?: number) {
    window.dispatchEvent(new CustomEvent("sol:open-attach", { detail: { name, ttlSecs } }));
  }

  return (
    <CommandPalette
      sessionId={sessionId}
      onSwitchTab={onSwitchTab}
      onTransfer={onTransfer}
      onOpenManage={onOpenManage}
      onOpenNeedsAction={onOpenNeedsAction}
      onOpenInvite={onOpenInvite}
      onNewSession={onNewSession}
      onOpenAttach={onOpenAttach}
    />
  );
}
