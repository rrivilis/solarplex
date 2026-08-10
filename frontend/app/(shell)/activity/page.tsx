"use client";

import { useQuery } from "@tanstack/react-query";
import RelativeTime from "@/components/RelativeTime";
import { DOT_COLOR, EVENT_LABEL, eventSummary } from "@/components/Timeline";
import EventTypeFilterBar from "@/components/EventTypeFilterBar";
import { useEventTypeFilter } from "@/lib/eventFilter";
import { signIn } from "@/lib/auth";
import { ActivityItem, getActivity } from "@/lib/activity";
import { useShellAuth } from "@/lib/shellAuth";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function ActivityPage() {
  useDocumentTitle("Recent Activity");
  const { authed } = useShellAuth();

  // Polled, not live-pushed — each session's live stream is its own isolated
  // broadcast channel with no cross-session bus to tap into; wiring a
  // live-pushed version is separate, larger backend work. 30s + refetch on
  // window focus (react-query default) is the same tradeoff made for the
  // inbox badge.
  const { data: items, isPending, isError } = useQuery({
    queryKey: ["activity"],
    queryFn: () => getActivity(150),
    enabled: authed,
    refetchInterval: 30_000,
  });

  // Same preference as the in-session Timeline's filter (shared localStorage
  // key) — turn off "Presence" once, actor.joined/detached noise (typically
  // the bulk of any feed) stays hidden everywhere.
  const { enabled: enabledCategories, toggle: toggleCategory, isEnabled } = useEventTypeFilter();
  const filteredItems = (items ?? []).filter(i => isEnabled(i.type));

  if (!authed) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Sign in to Solarplex</h1>
          <button
            onClick={() => signIn("/activity")}
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
      <div className="mb-5">
        <h1 className="text-base font-semibold text-primary mb-0.5">Recent Activity</h1>
        <p className="text-xs text-muted">
          Everything that happened across your sessions, most recent first
        </p>
      </div>

      {(items ?? []).length > 0 && (
        <div className="mb-4">
          <EventTypeFilterBar enabled={enabledCategories} onToggle={toggleCategory} />
        </div>
      )}

      {isPending ? (
        <div className="space-y-1.5">
          {[0, 1, 2, 3].map(i => (
            <div key={i} className="h-[38px] rounded-lg bg-surface-1 animate-pulse" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <p className="text-sm font-medium text-subtle mb-1">Couldn&apos;t load activity</p>
          <p className="text-xs text-muted">Your sign-in may have expired.</p>
        </div>
      ) : (items ?? []).length === 0 ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <div className="text-4xl mb-4 text-border select-none leading-none">⬡</div>
          <p className="text-sm font-medium text-subtle mb-1">No activity yet</p>
          <p className="text-xs text-muted leading-relaxed">
            Actions across your sessions will show up here.
          </p>
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <p className="text-sm font-medium text-subtle mb-1">No activity matches your filter</p>
          <p className="text-xs text-muted">Turn a category back on above to see it.</p>
        </div>
      ) : (
        <div className="space-y-0.5">
          {filteredItems.map(item => <ActivityRow key={item.id} item={item} />)}
        </div>
      )}
    </div>
  );
}

function ActivityRow({ item }: { item: ActivityItem }) {
  const actorNames = { [item.actor_id]: item.actor_name };
  const summary = eventSummary(item.event, actorNames);

  return (
    <a
      href={`/sessions/${item.session_id}`}
      className="density-row flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-surface-1 transition-colors duration-100 group"
    >
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DOT_COLOR[item.type] ?? "bg-surface-4"}`} />
      <span className="text-xs text-subtle shrink-0 w-32 truncate group-hover:text-accent-blue transition-colors duration-100">
        {item.session_name}
      </span>
      <span className="text-2xs text-muted shrink-0 w-28 truncate hidden sm:inline">
        {EVENT_LABEL[item.type] ?? item.type}
      </span>
      <span className="flex-1 min-w-0 text-xs text-muted truncate">{summary}</span>
      <RelativeTime date={item.timestamp} className="text-2xs text-muted shrink-0" />
    </a>
  );
}
