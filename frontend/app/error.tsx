"use client";

// Next.js App Router error boundary — catches render/render-time errors
// anywhere under app/ that aren't otherwise handled, so a stranger hitting
// an unexpected bug sees this instead of Next's default (stack trace in
// dev, a bare unstyled page in production) with no way back into the app.

import { useEffect } from "react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function GlobalErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useDocumentTitle("Error");
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
      <div className="w-[380px] rounded-xl border border-border bg-surface-1 panel-shine p-6 text-center">
        <div className="text-3xl mb-4 text-accent-red select-none leading-none">⬡</div>
        <h1 className="text-sm font-semibold text-primary mb-2">Something went wrong</h1>
        <p className="text-xs text-muted mb-6 leading-relaxed">
          An unexpected error occurred. You can try again, or head back to your sessions.
        </p>
        <div className="flex items-center justify-center gap-2">
          <a
            href="/"
            className="text-xs px-4 py-2 rounded-lg font-medium bg-surface-2 hover:bg-surface-3 text-subtle transition-colors"
          >
            Go home
          </a>
          <button
            onClick={reset}
            className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue text-surface-0 hover:bg-accent-blue/90 transition-colors"
          >
            Try again
          </button>
        </div>
      </div>
    </div>
  );
}
