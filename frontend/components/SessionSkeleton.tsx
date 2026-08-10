/**
 * SessionSkeleton — placeholder shell shown only before the first snapshot
 * has ever arrived for this session (state.snapshot === null in useSession).
 *
 * Deliberately NOT shown on later reconnects — once a snapshot has arrived
 * once, the last-known content stays visible while `phase` cycles through
 * "reconnecting", so a brief network blip doesn't blank out real content.
 * This exists specifically so a fresh attach shows an obvious "loading"
 * shape instead of a blank layout with a session ID that silently flips to
 * a name once data arrives.
 */

function Bar({ w, h = "h-3" }: { w: string; h?: string }) {
  return <div className={`${h} ${w} rounded bg-surface-3 animate-pulse`} />;
}

export default function SessionSkeleton() {
  return (
    <div className="flex h-full bg-surface-0 text-primary">
      {/* Left: StatusPanel-shaped skeleton */}
      <aside className="w-72 shrink-0 border-r border-border px-4 py-4 space-y-5">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-surface-3 animate-pulse" />
          <Bar w="w-20" />
        </div>
        <div className="space-y-2 pt-2 border-t border-border">
          <Bar w="w-16" h="h-2" />
          <Bar w="w-24" h="h-4" />
          <Bar w="w-32" h="h-2" />
        </div>
        <div className="space-y-2 pt-3 border-t border-border">
          <Bar w="w-14" h="h-2" />
          <Bar w="w-28" h="h-3" />
        </div>
        <div className="space-y-2 pt-3 border-t border-border">
          <Bar w="w-20" h="h-2" />
          <Bar w="w-full" h="h-3" />
          <Bar w="w-full" h="h-3" />
        </div>
      </aside>

      {/* Main column */}
      <div className="flex-1 flex flex-col min-w-0">
        <div className="h-[42px] px-5 border-b border-border flex items-center gap-4 shrink-0">
          <Bar w="w-32" h="h-3" />
          <div className="flex items-center gap-3">
            <Bar w="w-16" h="h-3" />
            <Bar w="w-16" h="h-3" />
            <Bar w="w-16" h="h-3" />
          </div>
        </div>
        <div className="flex-1 p-6 space-y-3">
          <Bar w="w-1/2" />
          <Bar w="w-2/3" />
          <Bar w="w-1/3" />
        </div>
      </div>

      {/* Right: NeedsAction-shaped skeleton */}
      <aside className="w-72 shrink-0 border-l border-border px-4 py-4 space-y-3">
        <Bar w="w-24" h="h-2" />
        <Bar w="w-full" h="h-16" />
      </aside>
    </div>
  );
}
