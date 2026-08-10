"use client";

import { memo, useEffect, useState } from "react";
import { useRelativeTime } from "@/hooks/useRelativeTime";
import { getTimestampMode } from "@/lib/preferences";

interface Props {
  date: string | Date | null | undefined;
  className?: string;
  /** Wrapping element — defaults to <time>. */
  as?: "time" | "span" | "p";
}

const ABSOLUTE_FORMAT: Intl.DateTimeFormatOptions = {
  year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
};

/**
 * Renders a timestamp — relative ("3 minutes ago", re-evaluated every 30s)
 * by default, or a fixed absolute date/time when the user's Settings
 * preference is set to it. Every existing call site gets this for free with
 * no changes of its own.
 *
 * `absolute` starts false and only flips in an effect, same reason
 * app/page.tsx's `authed` does: localStorage doesn't exist during SSR, so
 * reading it directly in the render body would make the client's hydration
 * pass disagree with the server-rendered HTML the moment "absolute" mode is
 * saved, and React throws a hydration mismatch. setTimestampMode already
 * reloads the page on change, so this one post-mount flip is enough — no
 * need for a live cross-tab listener on top of it.
 */
function RelativeTime({ date, className, as: Tag = "time" }: Props) {
  const relativeLabel = useRelativeTime(date);
  const [absolute, setAbsolute] = useState(false);
  useEffect(() => { setAbsolute(getTimestampMode() === "absolute"); }, []);

  if (!date) return null;
  const parsed = new Date(date);
  const label = absolute ? parsed.toLocaleString(undefined, ABSOLUTE_FORMAT) : relativeLabel;
  if (!label) return null;

  return (
    <Tag className={className} {...(Tag === "time" ? { dateTime: parsed.toISOString() } : {})}>
      {label}
    </Tag>
  );
}

// Every call site is a single row in a list (Sessions, Activity, Search,
// Teammates, Agents, Settings' sign-in history) — memoized so a parent
// list re-render (a react-query refetch, a filter toggle) doesn't force
// every row's RelativeTime to re-render too when its own props (date,
// className, as) haven't changed. Props are all primitives, so the
// default shallow comparison is exact, not an approximation.
export default memo(RelativeTime);
