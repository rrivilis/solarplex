"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import RelativeTime from "@/components/RelativeTime";
import { signIn } from "@/lib/auth";
import { getMailbox, markMailboxSeen, MailboxEntry, MailboxInviteEntry } from "@/lib/mailbox";
import { useShellAuth } from "@/lib/shellAuth";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const ROLE_LABEL: Record<string, string> = {
  owner: "Owner",
  collaborator: "Collaborator",
  observer: "Observer",
};

function inviteStatus(invite: MailboxInviteEntry["invite"]): { label: string; className: string } {
  if (invite.revoked_at) return { label: "Revoked", className: "text-muted bg-surface-3 border-border" };
  if (invite.redeemed_at) return { label: "Accepted", className: "text-accent-green bg-accent-green/10 border-accent-green/20" };
  if (new Date(invite.expires_at).getTime() <= Date.now()) return { label: "Expired", className: "text-muted bg-surface-3 border-border" };
  return { label: "Pending", className: "text-accent-blue bg-accent-blue/10 border-accent-blue/20" };
}

export default function InboxPage() {
  useDocumentTitle("Inbox");
  const { authed } = useShellAuth();

  const queryClient = useQueryClient();
  const { data: entries, isPending, isError } = useQuery({
    queryKey: ["mailbox"],
    queryFn: getMailbox,
    enabled: authed,
  });

  async function handleOpen(entry: MailboxEntry) {
    if (!entry.seen_at) {
      // Optimistic — don't block navigation on the mark-seen round trip.
      markMailboxSeen(entry.id).then(() => {
        queryClient.invalidateQueries({ queryKey: ["mailbox"] });
      });
    }
    if (entry.kind === "invite") {
      window.location.href = `/invite/${entry.invite.id}`;
    }
  }

  function handleDismiss(entry: MailboxEntry, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    markMailboxSeen(entry.id).then(() => {
      queryClient.invalidateQueries({ queryKey: ["mailbox"] });
    });
  }

  if (!authed) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Sign in to Solarplex</h1>
          <button
            onClick={() => signIn("/inbox")}
            className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue text-surface-0 hover:bg-accent-blue/90 transition-colors"
          >
            Sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-[740px] mx-auto py-10 px-8">
      <div className="mb-7">
        <h1 className="text-base font-semibold text-primary mb-0.5">Inbox</h1>
        <p className="text-xs text-muted">
          Invitations and other items addressed to you, wherever they came from
        </p>
      </div>

      {isPending ? (
        <div className="space-y-2">
          {[0, 1].map(i => (
            <div key={i} className="h-[70px] rounded-xl border border-border bg-surface-1 animate-pulse" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <p className="text-sm font-medium text-subtle mb-1">Couldn&apos;t load your inbox</p>
          <p className="text-xs text-muted">Your sign-in may have expired.</p>
        </div>
      ) : (entries ?? []).length === 0 ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <div className="text-4xl mb-4 text-border select-none leading-none">⬡</div>
          <p className="text-sm font-medium text-subtle mb-1">Nothing here yet</p>
          <p className="text-xs text-muted leading-relaxed">
            Session invitations addressed to you will show up here.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {(entries ?? []).map(entry => (
            <InboxRow key={entry.id} entry={entry} onOpen={handleOpen} onDismiss={handleDismiss} />
          ))}
        </div>
      )}
    </div>
  );
}

function InboxRow({
  entry,
  onOpen,
  onDismiss,
}: {
  entry: MailboxEntry;
  onOpen: (entry: MailboxEntry) => void;
  onDismiss: (entry: MailboxEntry, e: React.MouseEvent) => void;
}) {
  const unseen = !entry.seen_at;

  if (entry.kind !== "invite") {
    // Route pointed at something that no longer resolves — inert, dismiss-only.
    return (
      <div className="density-row flex items-center gap-3 px-4 py-3.5 rounded-xl border border-border bg-surface-1 opacity-60">
        <span className="flex-1 text-xs text-muted">This item is no longer available.</span>
        <button
          onClick={e => onDismiss(entry, e)}
          className="text-2xs px-2 py-1 rounded text-muted hover:text-subtle hover:bg-surface-2 transition-colors"
        >
          Dismiss
        </button>
      </div>
    );
  }

  const status = inviteStatus(entry.invite);

  return (
    <a
      href={`/invite/${entry.invite.id}`}
      onClick={e => { e.preventDefault(); onOpen(entry); }}
      className={`
        density-row
        group flex items-start gap-3
        px-4 py-3.5 rounded-xl
        border bg-surface-1 hover:bg-surface-2 hover:border-surface-4
        panel-shine transition-all duration-100 cursor-pointer
        ${unseen ? "border-accent-blue/30" : "border-border"}
      `}
    >
      {unseen && <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-accent-blue shrink-0" />}

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-4">
          <span className="font-medium text-sm text-primary truncate group-hover:text-accent-blue transition-colors duration-100">
            {entry.invite.session_name}
          </span>
          <span className={`shrink-0 text-2xs px-1.5 py-0.5 rounded border font-medium ${status.className}`}>
            {status.label}
          </span>
        </div>
        <div className="mt-1 flex items-center gap-3 text-2xs text-muted">
          <span>Invited as {ROLE_LABEL[entry.invite.role] ?? entry.invite.role}</span>
          <span className="text-border select-none">·</span>
          <span>by {entry.invite.invited_by_name}</span>
          <span className="text-border select-none">·</span>
          <RelativeTime date={entry.created_at} className="text-2xs text-muted" />
        </div>
      </div>

      <button
        onClick={e => onDismiss(entry, e)}
        className="shrink-0 text-2xs px-2 py-1 rounded text-muted opacity-0 group-hover:opacity-100 hover:text-subtle hover:bg-surface-3 transition-all"
      >
        {unseen ? "Mark seen" : "Dismiss"}
      </button>
    </a>
  );
}
