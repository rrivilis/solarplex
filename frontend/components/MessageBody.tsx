"use client";

import dynamic from "next/dynamic";
import MarkdownContent from "@/components/MarkdownContent";

const VoiceMemoPlayer = dynamic(() => import("./VoiceMemoPlayer"), { ssr: false });

// Voice-memo and file-upload messages embed the artifact id in the human-
// readable message content (e.g. "🎙️ Voice memo · 0:15 [artifact:01ABC...]")
// so the plain event log stays a single append-only text stream with no new
// wire format. Any renderer that prints message.posted content verbatim
// leaks that raw id instead of the intended player/attachment chip — this
// is the one shared place that un-does the embedding, so every consumer
// (in-session chat, the Log tab, cross-session sync panes) stays consistent.
export const VOICE_RE = /^🎙️ Voice memo · [\d:]+ \[artifact:([A-Z0-9]+)\]$/;
export const FILE_RE  = /^📎 (.+?) \[artifact:([A-Z0-9]+)\]$/;

export default function MessageBody({ sessionId, content }: { sessionId: string; content: string }) {
  const vm = VOICE_RE.exec(content);
  if (vm) return <VoiceMemoPlayer sessionId={sessionId} artifactId={vm[1]} />;

  const fm = FILE_RE.exec(content);
  if (fm) {
    return (
      <div className="flex items-center gap-2 mt-1 bg-surface-2 border border-border rounded-lg px-3 py-2 max-w-[260px]">
        <span className="text-sm select-none">📎</span>
        <span className="text-xs text-primary font-medium truncate flex-1 min-w-0">{fm[1]}</span>
        <span className="text-2xs text-muted shrink-0">artifact</span>
      </div>
    );
  }

  return <MarkdownContent content={content} />;
}
