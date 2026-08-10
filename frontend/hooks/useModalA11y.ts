"use client";

import { useEffect, useRef } from "react";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Focus trap + Escape-to-close + return-focus-on-close for a hand-rolled
 * modal/dialog overlay — the three behaviors `role="dialog"` implies but
 * doesn't provide on its own (the role is just an announcement; a screen
 * reader or keyboard user still needs Tab to actually stay inside the
 * dialog, and Escape to actually work, or the semantics are decorative).
 *
 * Prefer `vaul`'s `Drawer` (see ArtifactDrawer.tsx/NewSessionDrawer.tsx)
 * for new work — it gives you all of this for free. This hook exists for
 * the modals already built as a plain positioned `<div>` overlay, where
 * migrating to Drawer would be a bigger visual change than the a11y fix
 * warrants.
 *
 * @param open whether the modal is currently open
 * @param onClose called on Escape
 * @returns a ref to attach to the modal's outermost focusable container
 */
export function useModalA11y<T extends HTMLElement>(open: boolean, onClose: () => void) {
  const containerRef = useRef<T | null>(null);
  const triggerRef = useRef<Element | null>(null);

  useEffect(() => {
    if (!open) return;

    // The element that had focus right before this modal opened — almost
    // always the button that triggered it. Restored on close so keyboard
    // users land back where they were, not at the top of the page.
    triggerRef.current = document.activeElement;

    const container = containerRef.current;
    const focusables = container
      ? Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR))
      : [];
    (focusables[0] ?? container)?.focus();

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !container) return;

      const els = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR))
        .filter(el => el.offsetParent !== null); // skip hidden/collapsed elements
      if (els.length === 0) return;
      const first = els[0];
      const last = els[els.length - 1];

      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (triggerRef.current instanceof HTMLElement) {
        triggerRef.current.focus();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  return containerRef;
}
