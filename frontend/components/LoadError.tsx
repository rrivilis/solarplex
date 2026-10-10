"use client";

/**
 * Shown when a page's data request failed for a reason that is NOT "your
 * sign-in is no good". A refused sign-in (401) never gets here: `authFetch`
 * clears the token and the app shell drops back to the signed-out screen. What
 * remains is the server being unreachable, starting up, or briefly unable to
 * answer (e.g. its database is restarting), so this says that and offers a
 * retry rather than blaming the user's session.
 */
export default function LoadError({
  what,
  onRetry,
}: {
  /** What failed to load, lowercase and without an article: "sessions", "your inbox". */
  what: string;
  onRetry: () => void;
}) {
  return (
    <div
      role="alert"
      className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center"
    >
      <p className="text-sm font-medium text-subtle mb-1">Couldn&apos;t load {what}</p>
      <p className="text-xs text-muted mb-6">
        The server didn&apos;t respond as expected. It may be starting up or briefly unavailable.
      </p>
      <button
        onClick={onRetry}
        className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 border border-accent-blue/20 transition-colors"
      >
        Try again
      </button>
    </div>
  );
}
