"use client";

import { useEffect } from "react";

// WCAG 2.4.2 Page Titled — every route needs a title that describes its
// specific content, not the app-wide default from app/layout.tsx. Client
// components can't use Next's `metadata` export (server-only), so this sets
// document.title imperatively instead. Every "use client" page should call
// this once with its real content (never a raw ID) so client-side
// navigation never leaves a stale title from the previous route behind.
export function useDocumentTitle(title: string) {
  useEffect(() => {
    document.title = `${title} · Solarplex`;
  }, [title]);
}
