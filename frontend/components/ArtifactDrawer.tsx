"use client";

import { useEffect, useState } from "react";
import { Drawer } from "vaul";
import { ArtifactSummary } from "@/lib/types";
import { authFetch } from "@/lib/auth";
import { API_BASE } from "@/lib/env";
import LoadingSpinner from "@/components/LoadingSpinner";

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

interface Props {
  artifact: ArtifactSummary | null;
  sessionId: string;
  onClose: () => void;
}

const TYPE_BADGE: Record<string, { label: string; color: string; ext: string }> = {
  document:  { label: "doc",  color: "text-accent-blue   bg-accent-blue/10   border-accent-blue/20",   ext: "txt"  },
  code:      { label: "cod",  color: "text-accent-green  bg-accent-green/10  border-accent-green/20",  ext: "txt"  },
  code_diff: { label: "diff", color: "text-accent-green  bg-accent-green/10  border-accent-green/20",  ext: "diff" },
  plan:      { label: "pln",  color: "text-accent-purple bg-accent-purple/10 border-accent-purple/20", ext: "txt"  },
  report:    { label: "rpt",  color: "text-accent-amber  bg-accent-amber/10  border-accent-amber/20",  ext: "txt"  },
  spreadsheet:{ label: "tbl", color: "text-accent-green  bg-accent-green/10  border-accent-green/20",  ext: "csv"  },
  prompt:    { label: "prm",  color: "text-muted         bg-surface-3        border-border",            ext: "txt"  },
  other:     { label: "etc",  color: "text-muted         bg-surface-3        border-border",            ext: "txt"  },
};

// ── CSV parser for spreadsheets ───────────────────────────────────────────────

function parseCsv(raw: string): string[][] | null {
  const lines = raw.trim().split("\n");
  if (lines.length < 2) return null;
  const rows = lines.map(l => l.split(",").map(c => c.trim()));
  const width = rows[0].length;
  if (rows.some(r => r.length !== width)) return null;
  return rows;
}

// ── Content preview by artifact type ─────────────────────────────────────────

function ContentPreview({ type, content }: { type: string; content: string }) {
  const isCode = type === "code" || type === "code_diff";

  if (isCode) {
    const lines = content.split("\n");
    return (
      <div className="rounded-xl overflow-hidden border border-border bg-[#0c0c13]">
        <div className="flex items-center gap-1.5 px-4 py-2.5 border-b border-border/60 bg-surface-0">
          <span className="w-2.5 h-2.5 rounded-full bg-accent-red/50" />
          <span className="w-2.5 h-2.5 rounded-full bg-accent-amber/50" />
          <span className="w-2.5 h-2.5 rounded-full bg-accent-green/50" />
          <span className="ml-2 text-2xs text-muted font-mono">{type}</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-2xs font-mono leading-5">
            <tbody>
              {lines.map((line, i) => (
                <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                  <td className="select-none text-right pr-4 pl-4 py-0 text-border w-10 shrink-0">
                    {i + 1}
                  </td>
                  <td className="pr-4 py-0 text-[#c9d1d9] whitespace-pre">
                    {line || " "}
                  </td>
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
                    <th
                      key={i}
                      className="text-left px-3 py-2 border-b border-border text-subtle font-semibold whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {body.map((row, ri) => (
                  <tr
                    key={ri}
                    className="border-b border-border/40 odd:bg-surface-1 even:bg-surface-0 hover:bg-surface-2 transition-colors"
                  >
                    {row.map((cell, ci) => (
                      <td key={ci} className="px-3 py-1.5 text-primary whitespace-nowrap">
                        {cell}
                      </td>
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

  // Document / plan / report / prompt / other → prose
  // Detect section headings (lines that look like "## Heading" or "Heading:")
  const paragraphs = content.split(/\n{2,}/);
  return (
    <div className="space-y-3">
      {paragraphs.map((para, i) => {
        const mdHeading = para.match(/^#{1,3}\s+(.+)$/);
        if (mdHeading) {
          return (
            <p key={i} className="text-sm font-semibold text-primary">
              {mdHeading[1]}
            </p>
          );
        }
        return (
          <p key={i} className="text-sm text-primary leading-relaxed whitespace-pre-wrap">
            {para}
          </p>
        );
      })}
    </div>
  );
}

// ── Download helper ───────────────────────────────────────────────────────────

function triggerDownload(name: string, content: string, ext: string) {
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

// ── Open-in-new-tab helper ────────────────────────────────────────────────────

function openNewTab(name: string, content: string, type: string) {
  const isCode = type === "code" || type === "code_diff";
  const escaped = content.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${name}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0c0c14;
      color: #c9d1d9;
      font-family: ${isCode ? "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace" : "'Inter', system-ui, -apple-system, sans-serif"};
      font-size: 14px;
      line-height: 1.65;
      padding: 2rem;
      max-width: 900px;
      margin: 0 auto;
    }
    header {
      border-bottom: 1px solid #1e1e2e;
      padding-bottom: 1rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: baseline;
      gap: 0.75rem;
    }
    header h1 { font-size: 1rem; font-weight: 600; color: #e2e8f0; }
    header span { font-size: 0.75rem; color: #64748b; }
    pre { white-space: pre-wrap; word-break: break-all; }
    p   { white-space: pre-wrap; word-break: break-word; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <header>
    <h1>${name}</h1>
    <span>${type}</span>
  </header>
  ${isCode ? `<pre>${escaped}</pre>` : `<div>${escaped.split(/\n{2,}/).map(p => `<p>${p}</p>`).join("")}</div>`}
</body>
</html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener,noreferrer");
  // Give the tab time to load before revoking
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// ── Main drawer component ─────────────────────────────────────────────────────

export default function ArtifactDrawer({ artifact, sessionId, onClose }: Props) {
  const [full, setFull] = useState<ArtifactFull | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch full artifact (including storage_ref / content) when selection changes
  useEffect(() => {
    if (!artifact) {
      setFull(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setFull(null);

    authFetch(`${API_BASE}/sessions/${sessionId}/artifacts/${artifact.id}`)
      .then(r => {
        if (!r.ok) throw new Error(`Server returned ${r.status}`);
        return r.json() as Promise<ArtifactFull>;
      })
      .then(data => {
        if (!cancelled) {
          setFull(data);
          setLoading(false);
        }
      })
      .catch(e => {
        if (!cancelled) {
          setError((e as Error).message ?? "Unknown error");
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [artifact?.id, sessionId]);

  const badgeCfg = artifact
    ? (TYPE_BADGE[artifact.type] ?? { label: artifact.type.slice(0, 3), color: "text-muted bg-surface-3 border-border", ext: "txt" })
    : null;

  return (
    <Drawer.Root
      open={artifact !== null}
      onOpenChange={open => { if (!open) onClose(); }}
    >
      <Drawer.Portal>
        <Drawer.Overlay className="fixed inset-0 bg-black/50 backdrop-blur-[2px] z-40" />

        <Drawer.Content
          aria-describedby="artifact-drawer-desc"
          className="fixed bottom-0 left-0 right-0 z-50 flex flex-col rounded-t-2xl bg-surface-1 border-t border-border focus:outline-none"
          style={{ maxHeight: "78vh" }}
        >
          {/* Drag handle */}
          <div className="flex justify-center pt-3 pb-1 shrink-0 cursor-grab active:cursor-grabbing">
            <div className="w-10 h-1 rounded-full bg-border" />
          </div>

          {/* Header */}
          <div className="flex items-center justify-between px-5 pt-2.5 pb-3 border-b border-border shrink-0">
            <div className="flex items-center gap-3 min-w-0">
              {badgeCfg && (
                <span
                  className={`text-2xs font-mono font-semibold px-1.5 py-0.5 rounded border shrink-0 ${badgeCfg.color}`}
                >
                  {badgeCfg.label}
                </span>
              )}
              <div className="min-w-0">
                <Drawer.Title className="text-sm font-semibold text-primary truncate leading-tight">
                  {artifact?.name ?? ""}
                </Drawer.Title>
                {full ? (
                  <p id="artifact-drawer-desc" className="text-2xs text-muted mt-0.5">
                    v{full.version}
                    {full.created_by ? ` · by ${full.created_by}` : ""}
                  </p>
                ) : (
                  <p id="artifact-drawer-desc" className="sr-only">Artifact preview</p>
                )}
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close preview"
              className="ml-4 shrink-0 w-7 h-7 flex items-center justify-center rounded-lg text-muted hover:text-subtle hover:bg-surface-3 transition-all text-lg leading-none"
            >
              ×
            </button>
          </div>

          {/* Scrollable content body */}
          <div className="flex-1 overflow-y-auto px-5 py-4 min-h-0">
            {loading && (
              <LoadingSpinner size={22} label="Loading artifact…" className="h-40" />
            )}

            {error && !loading && (
              <div className="flex flex-col items-center justify-center gap-2 h-40">
                <span className="text-base text-accent-red select-none">⚠</span>
                <p className="text-xs text-accent-red">Failed to load artifact</p>
                <p className="text-2xs text-muted">{error}</p>
              </div>
            )}

            {full && !loading && (
              <ContentPreview type={full.type} content={full.storage_ref} />
            )}
          </div>

          {/* Footer actions */}
          <div className="flex items-center gap-3 px-5 py-3.5 border-t border-border bg-surface-1 shrink-0">
            {/* Preview in new tab */}
            <button
              onClick={() => {
                if (full) openNewTab(full.name, full.storage_ref, full.type);
              }}
              disabled={!full}
              className="flex-1 flex items-center justify-center gap-2 text-xs font-medium py-2 px-4 rounded-xl
                         bg-surface-3 border border-border text-subtle
                         hover:bg-surface-4 hover:border-subtle hover:text-primary
                         transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M6 3H3a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-3" />
                <path d="M9 1h6v6" />
                <path d="M15 1 8 8" />
              </svg>
              Open in new tab
            </button>

            {/* Download */}
            <button
              onClick={() => {
                if (full && badgeCfg) triggerDownload(full.name, full.storage_ref, badgeCfg.ext);
              }}
              disabled={!full}
              className="flex-1 flex items-center justify-center gap-2 text-xs font-medium py-2 px-4 rounded-xl
                         bg-accent-blue/10 border border-accent-blue/25 text-accent-blue
                         hover:bg-accent-blue/20 hover:border-accent-blue/40
                         transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M8 1v9" />
                <path d="M4 7l4 4 4-4" />
                <path d="M2 13h12" />
              </svg>
              Download
            </button>
          </div>
        </Drawer.Content>
      </Drawer.Portal>
    </Drawer.Root>
  );
}
