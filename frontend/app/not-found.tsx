// Next.js App Router 404 — covers any unmatched route (e.g. a bad/stale
// invite link, a mistyped URL) and any explicit notFound() call. Without
// this, unmatched routes fall through to Next's bare default 404.

import type { Metadata } from "next";

// A server component (no "use client"), so the idiomatic `metadata` export
// works directly here instead of the imperative useDocumentTitle hook used
// on client pages — see hooks/useDocumentTitle.ts.
export const metadata: Metadata = { title: "Page not found · Solarplex" };

export default function NotFound() {
  return (
    <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
      <div className="w-[380px] rounded-xl border border-border bg-surface-1 panel-shine p-6 text-center">
        <div className="text-3xl mb-4 text-muted select-none leading-none">⬡</div>
        <h1 className="text-sm font-semibold text-primary mb-2">Page not found</h1>
        <p className="text-xs text-muted mb-6 leading-relaxed">
          This page doesn&apos;t exist, or the link may have expired.
        </p>
        <a
          href="/"
          className="inline-block text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 border border-accent-blue/20 transition-colors"
        >
          Go to sessions
        </a>
      </div>
    </div>
  );
}
