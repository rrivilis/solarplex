import { useSyncExternalStore } from "react";
import { formatDistanceToNow } from "date-fns";

// One shared 30s clock for every RelativeTime instance on the page, instead
// of one independent setInterval per row. A 150-row Activity feed (or a
// growing Sessions list) used to mean 150 separate timers all created at
// slightly different mount times, all recomputing formatDistanceToNow and
// re-rendering independently roughly every 30s — a small, recurring stutter
// that shows up exactly as "sometimes laggy," not "always slow." This is the
// same recompute shared across every subscriber via one timer instead.
let tick = 0;
const listeners = new Set<() => void>();
let intervalId: ReturnType<typeof setInterval> | null = null;

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // Lazily started on first subscriber, torn down when the last one
  // unmounts — no ticking clock running on pages with no relative
  // timestamps at all.
  if (intervalId === null) {
    intervalId = setInterval(() => {
      tick++;
      listeners.forEach(l => l());
    }, 30_000);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && intervalId !== null) {
      clearInterval(intervalId);
      intervalId = null;
    }
  };
}

function getSnapshot(): number {
  return tick;
}

function getServerSnapshot(): number {
  return 0;
}

/**
 * Returns a human-readable relative time string (e.g. "3 minutes ago") that
 * re-renders on the shared 30s clock above so the UI ticks forward without
 * a page refresh.
 *
 * @param date ISO string, Date object, or null/undefined.
 */
export function useRelativeTime(date: string | Date | null | undefined): string {
  // Subscribing is what triggers the re-render every tick; the returned
  // number itself is unused, same as the old per-instance counter was.
  useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  if (!date) return "";
  try {
    return formatDistanceToNow(new Date(date), { addSuffix: true });
  } catch {
    return "";
  }
}
