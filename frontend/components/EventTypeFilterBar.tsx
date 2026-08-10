"use client";

import { EVENT_CATEGORIES, EventCategory } from "@/lib/eventFilter";

export default function EventTypeFilterBar({
  enabled, onToggle,
}: {
  enabled: Set<EventCategory>;
  onToggle: (cat: EventCategory) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {EVENT_CATEGORIES.map(c => {
        const on = enabled.has(c.key);
        return (
          <button
            key={c.key}
            onClick={() => onToggle(c.key)}
            aria-pressed={on}
            className={`text-2xs px-2 py-1 rounded-full border transition-colors ${
              on
                ? "bg-accent-blue/10 border-accent-blue/30 text-accent-blue"
                : "bg-surface-2 border-border text-muted hover:text-subtle"
            }`}
          >
            {c.label}
          </button>
        );
      })}
    </div>
  );
}
