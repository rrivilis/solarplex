"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TooltipProvider } from "@radix-ui/react-tooltip";
import { MotionConfig } from "framer-motion";
import { Toaster } from "sonner";
import { useEffect, useState } from "react";
import GlobalCommandPalette from "@/components/GlobalCommandPalette";
import { captureSpTokenFromHash } from "@/lib/auth";
import { applyStoredDensity } from "@/lib/preferences";

export default function Providers({ children }: { children: React.ReactNode }) {
  // Each browser session gets its own QueryClient (no cross-request data sharing).
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: { staleTime: 30_000, retry: 1 },
    },
  }));

  // Capture an sp_token delivered via #sp_token=... after the OIDC callback
  // redirect. Runs on every mount; a no-op when there's no hash to read.
  useEffect(() => {
    captureSpTokenFromHash();
    // Imperative DOM mutation post-mount, not a render input — safe against
    // hydration mismatches (unlike reading localStorage during render, which
    // is exactly why RelativeTime's absolute-mode flag is state+effect
    // instead of a direct read).
    applyStoredDensity();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      {/* reducedMotion="user": every motion.* / AnimatePresence animation
          app-wide automatically drops transform-based motion (rotate,
          scale, x, y — the disorienting kind WCAG 2.3.3 cares about) for
          users with the OS-level prefers-reduced-motion setting on, while
          leaving opacity crossfades intact. One switch instead of auditing
          every transition prop individually. */}
      <MotionConfig reducedMotion="user">
        <TooltipProvider delayDuration={400}>
          {children}
          {/* Global ⌘K palette — works on every page, session-aware via URL */}
          <GlobalCommandPalette />
          <Toaster
            position="bottom-right"
            toastOptions={{
              style: {
                background: "var(--color-surface-2, #1e1e2e)",
                border: "1px solid var(--color-border, #2a2a3e)",
                color: "var(--color-primary, #e2e8f0)",
                fontSize: "12px",
              },
            }}
          />
        </TooltipProvider>
      </MotionConfig>
    </QueryClientProvider>
  );
}
