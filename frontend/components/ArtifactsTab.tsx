"use client";

import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { ArtifactSummary, WsEnvelope } from "@/lib/types";
import RelativeTime from "@/components/RelativeTime";
import { authFetch } from "@/lib/auth";
import { API_BASE } from "@/lib/env";
import LoadingSpinner from "@/components/LoadingSpinner";

interface Props {
  artifacts: ArtifactSummary[];
  events: WsEnvelope[];
  sessionId: string;
  /** actor_id -> display name, resolved from the session snapshot's
   *  members list — same pattern as Timeline/Messages/ContextTab. This tab
   *  was the one place still missing it, showing raw actor_ids for both
   *  the list row's "by {creator}" and the preview header's "by {created_by}". */
  actorNames?: Record<string, string>;
}

interface ArtifactFull {
  id: string;
  session_id: string;
  created_by: string;
  name: string;
  type: string;
  storage_ref: string;
  version: number;
  created_at: string;
  updated_at: string;
}

const TYPE_BADGE: Record<string, { label: string; color: string; ext: string }> = {
  document:    { label: "doc",  color: "text-accent-blue   bg-accent-blue/10   border-accent-blue/20",   ext: "txt"    },
  code:        { label: "cod",  color: "text-accent-green  bg-accent-green/10  border-accent-green/20",  ext: "txt"    },
  code_diff:   { label: "diff", color: "text-accent-green  bg-accent-green/10  border-accent-green/20",  ext: "diff"   },
  plan:        { label: "pln",  color: "text-accent-purple bg-accent-purple/10 border-accent-purple/20", ext: "txt"    },
  report:      { label: "rpt",  color: "text-accent-amber  bg-accent-amber/10  border-accent-amber/20",  ext: "txt"    },
  spreadsheet: { label: "tbl",  color: "text-accent-green  bg-accent-green/10  border-accent-green/20",  ext: "csv"    },
  prompt:      { label: "prm",  color: "text-muted         bg-surface-3        border-border",            ext: "txt"    },
  voice_memo:  { label: "mic",  color: "text-accent-purple bg-accent-purple/10 border-accent-purple/20", ext: "webm"   },
  audio:       { label: "aud",  color: "text-accent-purple bg-accent-purple/10 border-accent-purple/20", ext: "webm"   },
  other:       { label: "etc",  color: "text-muted         bg-surface-3        border-border",            ext: "txt"    },
};

// ── CSV parser ────────────────────────────────────────────────────────────────

function parseCsv(raw: string): string[][] | null {
  const lines = raw.trim().split("\n");
  if (lines.length < 2) return null;
  const rows = lines.map(l => l.split(",").map(c => c.trim()));
  const width = rows[0].length;
  if (rows.some(r => r.length !== width)) return null;
  return rows;
}

// ── Content preview ───────────────────────────────────────────────────────────

function ContentPreview({ type, content }: { type: string; content: string }) {
  // Whiteboard: dual-format JSON {scene, preview}
  if (type === "whiteboard") {
    try {
      const parsed = JSON.parse(content);
      if (parsed.preview && typeof parsed.preview === "string") {
        return (
          <div className="flex items-center justify-center p-4 bg-[#0c0c13] rounded-xl border border-border overflow-hidden">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={parsed.preview}
              alt="Whiteboard"
              className="max-w-full object-contain rounded"
              style={{ maxHeight: "400px" }}
            />
          </div>
        );
      }
    } catch { /* fall through */ }
    return <p className="text-xs text-muted text-center py-8">Save the whiteboard to generate a preview.</p>;
  }

  // Audio (voice memo, any audio/* data URL)
  if (type === "voice_memo" || type === "audio" || content.startsWith("data:audio/")) {
    return (
      <div className="flex flex-col gap-4 p-5 bg-[#0c0c13] rounded-xl border border-border">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-purple/15 border border-accent-purple/25 flex items-center justify-center shrink-0">
            {/* Waveform icon */}
            <svg width="18" height="14" viewBox="0 0 18 14" fill="none" stroke="currentColor"
              strokeWidth="1.6" strokeLinecap="round" className="text-accent-purple" aria-hidden>
              <path d="M1 7h1" />
              <path d="M4 4v6" />
              <path d="M7 2v10" />
              <path d="M10 5v4" />
              <path d="M13 3v8" />
              <path d="M16 4v6" />
            </svg>
          </div>
          <div>
            <p className="text-xs font-semibold text-primary">Voice Memo</p>
            <p className="text-2xs text-muted">Audio recording · click play to listen</p>
          </div>
        </div>

        {/* Native audio player */}
        <audio
          controls
          src={content}
          preload="metadata"
          className="w-full"
          style={{ colorScheme: "dark", height: "36px" }}
        />
      </div>
    );
  }

  // Standalone image (base64 or URL)
  if (content.startsWith("data:image/") || /\.(png|jpe?g|gif|webp|svg)$/i.test(content)) {
    return (
      <div className="flex items-center justify-center p-4 bg-[#0c0c13] rounded-xl border border-border overflow-hidden">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={content}
          alt={type}
          className="max-w-full object-contain rounded"
          style={{ maxHeight: "400px" }}
        />
      </div>
    );
  }

  if (type === "code" || type === "code_diff") {
    const lines = content.split("\n");
    return (
      <div className="rounded-xl overflow-hidden border border-border bg-[#0c0c13]">
        <div className="flex items-center gap-1.5 px-4 py-2.5 border-b border-border/60 bg-surface-0">
          <span className="w-2 h-2 rounded-full bg-accent-red/50" />
          <span className="w-2 h-2 rounded-full bg-accent-amber/50" />
          <span className="w-2 h-2 rounded-full bg-accent-green/50" />
          <span className="ml-2 text-2xs text-muted font-mono">{type}</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-2xs font-mono leading-5">
            <tbody>
              {lines.map((line, i) => (
                <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                  <td className="select-none text-right pr-4 pl-4 py-0 text-border w-10 shrink-0">{i + 1}</td>
                  <td className="pr-4 py-0 text-[#c9d1d9] whitespace-pre">{line || " "}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  if (type === "spreadsheet") {
    const rows = parseCsv(content);
    if (rows) {
      const [header, ...body] = rows;
      return (
        <div className="rounded-xl overflow-hidden border border-border">
          <div className="overflow-x-auto">
            <table className="text-2xs w-full border-collapse">
              <thead>
                <tr className="bg-surface-2">
                  {header.map((h, i) => (
                    <th key={i} className="text-left px-3 py-2 border-b border-border text-subtle font-semibold whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {body.map((row, ri) => (
                  <tr key={ri} className="border-b border-border/40 odd:bg-surface-1 even:bg-surface-0 hover:bg-surface-2 transition-colors">
                    {row.map((cell, ci) => (
                      <td key={ci} className="px-3 py-1.5 text-primary whitespace-nowrap">{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );
    }
  }

  // Document / plan / report / prompt / other → GitHub-style markdown
  return (
    <div className="prose-solarplex">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>
        {content}
      </ReactMarkdown>
    </div>
  );
}

// ── Download / open helpers ───────────────────────────────────────────────────

function triggerDownload(name: string, content: string, ext: string) {
  // For images, download as-is from the data URL
  if (content.startsWith("data:image/")) {
    const a = document.createElement("a");
    a.href = content;
    const safeName = name.replace(/[^a-z0-9_\-. ]/gi, "_");
    a.download = safeName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    return;
  }
  const safeName = name.replace(/[^a-z0-9_\-. ]/gi, "_");
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = safeName.endsWith(`.${ext}`) ? safeName : `${safeName}.${ext}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function openNewTab(name: string, content: string, type: string) {
  if (content.startsWith("data:image/")) {
    window.open(content, "_blank", "noopener,noreferrer");
    return;
  }
  const isCode = type === "code" || type === "code_diff";
  const escaped = content.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${name}</title>
  <style>
    body { background:#0c0c14;color:#c9d1d9;font-family:${isCode ? "monospace" : "system-ui,sans-serif"};font-size:14px;line-height:1.65;padding:2rem;max-width:900px;margin:0 auto; }
    header { border-bottom:1px solid #1e1e2e;padding-bottom:1rem;margin-bottom:1.5rem;display:flex;align-items:baseline;gap:.75rem; }
    header h1 { font-size:1rem;font-weight:600;color:#e2e8f0; }
    header span { font-size:.75rem;color:#64748b; }
    pre { white-space:pre-wrap;word-break:break-all; }
    p { white-space:pre-wrap;word-break:break-word;margin-bottom:1rem; }
  </style>
</head>
<body>
  <header><h1>${name}</h1><span>${type}</span></header>
  ${isCode ? `<pre>${escaped}</pre>` : `<div>${escaped.split(/\n{2,}/).map(p => `<p>${p}</p>`).join("")}</div>`}
</body>
</html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener,noreferrer");
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ArtifactsTab({ artifacts, events, sessionId, actorNames }: Props) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [full, setFull] = useState<ArtifactFull | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Build enrichment map from events
  const meta: Record<string, { creator: string; timestamp: string; updates: number }> = {};
  events.forEach(e => {
    if (!e.payload) return;
    const p = e.payload as Record<string, unknown>;
    const aid = p.artifact_id as string | undefined;
    if (!aid) return;
    if (e.type === "artifact.created") {
      meta[aid] = { creator: e.actor ?? "unknown", timestamp: e.timestamp ?? "", updates: 0 };
    } else if (e.type === "artifact.updated") {
      if (meta[aid]) meta[aid].updates += 1;
      if (e.timestamp) meta[aid] = { ...meta[aid], timestamp: e.timestamp };
    }
  });

  const selected = artifacts.find(a => a.id === selectedId) ?? null;

  // Fetch full content when selection changes
  useEffect(() => {
    if (!selectedId) { setFull(null); setError(null); return; }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setFull(null);
    authFetch(`${API_BASE}/sessions/${sessionId}/artifacts/${selectedId}`)
      .then(r => { if (!r.ok) throw new Error(`${r.status}`); return r.json() as Promise<ArtifactFull>; })
      .then(d => { if (!cancelled) { setFull(d); setLoading(false); } })
      .catch(e => { if (!cancelled) { setError((e as Error).message); setLoading(false); } });
    return () => { cancelled = true; };
  }, [selectedId, sessionId]);

  const badgeCfg = selected
    ? (TYPE_BADGE[selected.type] ?? { label: selected.type.slice(0, 3), color: "text-muted bg-surface-3 border-border", ext: "txt" })
    : null;

  if (artifacts.length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-2 text-center px-8">
        <div className="text-3xl text-border select-none leading-none">⬡</div>
        <p className="text-xs text-muted font-medium">No artifacts yet</p>
        <p className="text-2xs text-muted leading-relaxed">
          Documents, plans, code, and reports created by agents
          <br />will appear here for review and download.
        </p>
      </div>
    );
  }

  const previewOpen = selectedId !== null;

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
      {/* ── Artifact list ── */}
      <div
        className="overflow-y-auto transition-all duration-300"
        style={{ flex: previewOpen ? "0 0 auto" : "1 1 auto", maxHeight: previewOpen ? "40%" : undefined }}
      >
        <div className="px-5 py-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xs font-semibold text-subtle uppercase tracking-widest">Artifacts</h2>
            <span className="text-2xs text-muted">{artifacts.length} total</span>
          </div>

          <div className="space-y-2">
            {artifacts.map(a => {
              const badge = TYPE_BADGE[a.type] ?? { label: a.type.slice(0, 3), color: "text-muted bg-surface-3 border-border" };
              const m = meta[a.id];
              const isSelected = selectedId === a.id;
              return (
                <button
                  key={a.id}
                  onClick={() => setSelectedId(isSelected ? null : a.id)}
                  className={`group w-full text-left flex items-center gap-3 px-3.5 py-3 rounded-xl border transition-all
                    ${isSelected
                      ? "bg-surface-3 border-accent-blue/30 ring-1 ring-accent-blue/20"
                      : "bg-surface-1 border-border hover:bg-surface-2 hover:border-surface-4"
                    }`}
                >
                  <span className={`text-2xs font-mono font-semibold px-1.5 py-0.5 rounded border shrink-0 ${badge.color}`}>
                    {badge.label}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className={`text-xs font-medium truncate transition-colors ${isSelected ? "text-accent-blue" : "text-primary group-hover:text-accent-blue"}`}>
                      {a.name}
                    </p>
                    <p className="text-2xs text-muted mt-0.5">
                      {m ? (
                        <>
                          by {actorNames?.[m.creator] ?? m.creator}
                          {m.timestamp && <>{" · "}<RelativeTime date={m.timestamp} as="span" /></>}
                          {m.updates > 0 && ` · v${m.updates + 1}`}
                        </>
                      ) : a.type}
                    </p>
                  </div>
                  {/* Chevron */}
                  <svg
                    width="12" height="12" viewBox="0 0 12 12" fill="none"
                    stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
                    className={`shrink-0 transition-all duration-200 ${isSelected ? "text-accent-blue rotate-90" : "text-muted group-hover:text-subtle"}`}
                    aria-hidden
                  >
                    <path d="M4 2l4 4-4 4" />
                  </svg>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Inline preview panel ── */}
      {previewOpen && (
        <div className="flex flex-col flex-1 min-h-0 border-t border-border bg-surface-0">
          {/* Preview header */}
          <div className="flex items-center gap-3 px-5 py-3 border-b border-border shrink-0 bg-surface-1">
            {badgeCfg && (
              <span className={`text-2xs font-mono font-semibold px-1.5 py-0.5 rounded border shrink-0 ${badgeCfg.color}`}>
                {badgeCfg.label}
              </span>
            )}
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-primary truncate">{selected?.name}</p>
              {full && (
                <p className="text-2xs text-muted mt-0.5">
                  v{full.version}{full.created_by ? ` · by ${actorNames?.[full.created_by] ?? full.created_by}` : ""}
                </p>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                onClick={() => { if (full) openNewTab(full.name, full.storage_ref, full.type); }}
                disabled={!full}
                title="Open in new tab"
                className="flex items-center gap-1.5 text-2xs px-2.5 py-1.5 rounded-lg bg-surface-3 border border-border text-subtle
                           hover:text-primary hover:bg-surface-4 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M6 3H3a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-3" /><path d="M9 1h6v6" /><path d="M15 1 8 8" />
                </svg>
                Open
              </button>
              <button
                onClick={() => { if (full && badgeCfg) triggerDownload(full.name, full.storage_ref, badgeCfg.ext); }}
                disabled={!full}
                title="Download"
                className="flex items-center gap-1.5 text-2xs px-2.5 py-1.5 rounded-lg bg-accent-blue/10 border border-accent-blue/25 text-accent-blue
                           hover:bg-accent-blue/20 hover:border-accent-blue/40 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M8 1v9" /><path d="M4 7l4 4 4-4" /><path d="M2 13h12" />
                </svg>
                Download
              </button>
              <button
                onClick={() => setSelectedId(null)}
                aria-label="Close preview"
                className="ml-1 w-7 h-7 flex items-center justify-center rounded-lg text-muted hover:text-subtle hover:bg-surface-3 transition-all text-base leading-none"
              >
                ×
              </button>
            </div>
          </div>

          {/* Preview content */}
          <div className="flex-1 overflow-y-auto px-5 py-4">
            {loading && (
              <LoadingSpinner size={22} label="Loading…" className="h-32" />
            )}
            {error && !loading && (
              <div className="flex flex-col items-center justify-center gap-2 h-32">
                <span className="text-base text-accent-red">⚠</span>
                <p className="text-xs text-accent-red">Failed to load artifact</p>
                <p className="text-2xs text-muted">{error}</p>
              </div>
            )}
            {full && !loading && (
              <ContentPreview type={full.type} content={full.storage_ref} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
