"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import RelativeTime from "@/components/RelativeTime";
import { DOT_COLOR, EVENT_LABEL, eventSummary } from "@/lib/eventTaxonomy";
import { signIn } from "@/lib/auth";
import { search, ActorHit, ArtifactHit, EventHit, SessionHit } from "@/lib/search";
import { useShellAuth } from "@/lib/shellAuth";
import { useDebounced } from "@/hooks/useDebounced";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function SearchPage() {
  useDocumentTitle("Search");
  const { authed } = useShellAuth();
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounced(query, 250);

  const { data, isFetching } = useQuery({
    queryKey: ["search", debouncedQuery],
    queryFn: () => search(debouncedQuery),
    enabled: authed && debouncedQuery.trim().length >= 2,
  });

  const hasQuery = debouncedQuery.trim().length >= 2;
  const results = data ?? { sessions: [], artifacts: [], actors: [], events: [] };
  const totalHits = results.sessions.length + results.artifacts.length + results.actors.length + results.events.length;

  if (!authed) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Sign in to Solarplex</h1>
          <button
            onClick={() => signIn("/search")}
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
        <h1 className="text-base font-semibold text-primary mb-0.5">Search</h1>
        <p className="text-xs text-muted">
          Sessions, artifacts, actors, and event content scoped to sessions you&apos;re a member of.
        </p>
      </div>

      <div className="relative mb-6">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8"
          className="absolute left-3.5 top-1/2 -translate-y-1/2 text-muted pointer-events-none">
          <circle cx="7" cy="7" r="5" />
          <path d="M11 11l3 3" />
        </svg>
        <input
          autoFocus
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder='Search, or filter with type: session: actor: such as type:artifact session:standup logo'
          aria-label="Search"
          className="w-full pl-9 pr-3 py-2.5 rounded-xl bg-surface-1 border border-border text-sm text-primary outline-none placeholder:text-muted focus:border-accent-blue/40 transition-colors"
        />
      </div>

      {!hasQuery ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <div className="text-4xl mb-4 text-border select-none leading-none">⬡</div>
          <p className="text-sm font-medium text-subtle mb-1">Type at least 2 characters</p>
          <p className="text-xs text-muted mb-3">Also accessible via ⌘K from any page.</p>
          <p className="text-2xs text-muted">
            Narrow with <code className="px-1 py-0.5 rounded bg-surface-2 text-subtle">type:</code>,{" "}
            <code className="px-1 py-0.5 rounded bg-surface-2 text-subtle">session:</code>, or{" "}
            <code className="px-1 py-0.5 rounded bg-surface-2 text-subtle">actor:</code> 
            <br />
            Quote a value with spaces, e.g. <code className="px-1 py-0.5 rounded bg-surface-2 text-subtle">session:&quot;weekly sync&quot;</code>
          </p>
        </div>
      ) : isFetching && !data ? (
        <div className="space-y-1.5">
          {[0, 1, 2].map(i => <div key={i} className="h-[38px] rounded-lg bg-surface-1 animate-pulse" />)}
        </div>
      ) : totalHits === 0 ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <p className="text-sm font-medium text-subtle mb-1">No results for &quot;{debouncedQuery}&quot;</p>
          <p className="text-xs text-muted">Try a different term, or check you&apos;re a member of the session it&apos;s in.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {results.sessions.length > 0 && (
            <ResultGroup label="Sessions">
              {results.sessions.map(s => <SessionRow key={s.id} hit={s} />)}
            </ResultGroup>
          )}
          {results.artifacts.length > 0 && (
            <ResultGroup label="Artifacts">
              {results.artifacts.map(a => <ArtifactRow key={a.id} hit={a} />)}
            </ResultGroup>
          )}
          {results.actors.length > 0 && (
            <ResultGroup label="People">
              {results.actors.map(a => <ActorRow key={a.id} hit={a} />)}
            </ResultGroup>
          )}
          {results.events.length > 0 && (
            <ResultGroup label="Events">
              {results.events.map(e => <EventRow key={e.id} hit={e} />)}
            </ResultGroup>
          )}
        </div>
      )}
    </div>
  );
}

function ResultGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-2xs font-semibold text-muted uppercase tracking-widest mb-1.5 px-1">{label}</p>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function SessionRow({ hit }: { hit: SessionHit }) {
  return (
    <a
      href={`/sessions/${hit.id}`}
      className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-surface-1 transition-colors duration-100 group"
    >
      <span className="text-sm shrink-0 text-border select-none">⬡</span>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-subtle group-hover:text-accent-blue transition-colors truncate">{hit.name}</p>
        {hit.description && <p className="text-2xs text-muted truncate">{hit.description}</p>}
      </div>
      <span className="text-2xs text-muted shrink-0">{hit.status}</span>
    </a>
  );
}

function ArtifactRow({ hit }: { hit: ArtifactHit }) {
  return (
    <a
      href={`/sessions/${hit.session_id}?tab=artifacts`}
      className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-surface-1 transition-colors duration-100 group"
    >
      <span className="text-2xs font-mono px-1.5 py-0.5 rounded border border-border bg-surface-2 text-muted shrink-0">
        {hit.type.slice(0, 3)}
      </span>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-subtle group-hover:text-accent-blue transition-colors truncate">{hit.name}</p>
        <p className="text-2xs text-muted truncate">in {hit.session_name} · by {hit.created_by_name}</p>
      </div>
    </a>
  );
}

function ActorRow({ hit }: { hit: ActorHit }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg">
      <div className="w-6 h-6 rounded-full shrink-0 bg-accent-blue/15 text-accent-blue ring-1 ring-accent-blue/20 flex items-center justify-center text-[9px] font-bold">
        {hit.name.slice(0, 2).toUpperCase()}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-subtle truncate">{hit.name}</p>
        {hit.email && <p className="text-2xs text-muted truncate">{hit.email}</p>}
      </div>
      <span className="text-2xs text-muted shrink-0">{hit.type}</span>
    </div>
  );
}

function EventRow({ hit }: { hit: EventHit }) {
  const actorNames = { [hit.actor_id]: hit.actor_name };
  const envelope = {
    protocol_version: 1, id: hit.id, session_id: hit.session_id, type: hit.type,
    actor: hit.actor_id, timestamp: hit.timestamp, payload: hit.payload,
  };
  return (
    <a
      href={`/sessions/${hit.session_id}`}
      className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-surface-1 transition-colors duration-100 group"
    >
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DOT_COLOR[hit.type] ?? "bg-surface-4"}`} />
      <span className="text-2xs text-subtle shrink-0 w-28 truncate group-hover:text-accent-blue transition-colors">{hit.session_name}</span>
      <span className="text-2xs text-muted shrink-0 w-24 truncate hidden sm:inline">{EVENT_LABEL[hit.type] ?? hit.type}</span>
      <span className="flex-1 min-w-0 text-xs text-muted truncate">{eventSummary(envelope, actorNames)}</span>
      <RelativeTime date={hit.timestamp} className="text-2xs text-muted shrink-0" />
    </a>
  );
}
