"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Excalidraw, exportToBlob } from "@excalidraw/excalidraw";
import "@excalidraw/excalidraw/index.css";
import { toast } from "sonner";
import { API_BASE } from "@/lib/env";
import { authFetch, maybeToastRateLimited } from "@/lib/auth";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ExcalidrawAPI = any;

interface SavedScene {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  elements: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  appState: Record<string, any>;
}

interface Props {
  sessionId: string;
  actorId: string;
  /** Called after a successful save so the parent can refresh its artifact list. */
  onSaveSuccess?: () => void;
}

export default function Whiteboard({ sessionId, actorId, onSaveSuccess }: Props) {
  const apiRef                                        = useRef<ExcalidrawAPI>(null);
  const [initialData, setInitialData]                 = useState<SavedScene | null>(null);
  const [artifactId, setArtifactId]                   = useState<string | null>(null);
  const [loading, setLoading]                         = useState(true);
  const [saving, setSaving]                           = useState(false);
  const [savedAt, setSavedAt]                         = useState<Date | null>(null);
  const [saveError, setSaveError]                     = useState<string | null>(null);

  // ── Load the most recent whiteboard artifact on mount ────────────────────────
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const listRes = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts`);
        if (!listRes.ok) return;
        // The API returns ArtifactRow which has `type` (not `artifact_type`).
        const list: { id: string; type: string; created_at: string }[] =
          await listRes.json();
        const wbs = list
          .filter(a => a.type === "whiteboard")
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
        if (wbs.length === 0) return;
        const detail = await authFetch(
          `${API_BASE}/sessions/${sessionId}/artifacts/${wbs[0].id}`,
        );
        if (!detail.ok) return;
        const full: { id: string; storage_ref: string } = await detail.json();
        if (!cancelled) {
          setArtifactId(full.id);
          try {
            const raw = JSON.parse(full.storage_ref);
            // Support dual-format {scene, preview} (new) and bare scene (legacy).
            const scene = raw.scene ?? raw;
            // Drop volatile fields that cause Excalidraw to crash on reload.
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const { collaborators: _c, isLoading: _l, errorMessage: _e, ...safeAppState } = scene.appState ?? {};
            setInitialData({ elements: scene.elements ?? [], appState: safeAppState });
          } catch { /* not valid JSON, start blank */ }
        }
      } catch { /* network error — start blank */ }
    }
    load().finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [sessionId]);

  // ── Save ─────────────────────────────────────────────────────────────────────
  const saveAsArtifact = useCallback(async () => {
    const api: ExcalidrawAPI = apiRef.current;
    if (!api) {
      setSaveError("Whiteboard not ready — try again in a moment.");
      return;
    }
    setSaving(true);
    setSaveError(null);
    try {
      const elements = api.getSceneElements();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { collaborators: _c, isLoading: _l, errorMessage: _e, ...safeAppState } = api.getAppState();
      const files = api.getFiles();

      // Export a PNG preview so the artifact panel can show a real image.
      let preview = "";
      try {
        const blob = await exportToBlob({
          elements,
          appState: { ...safeAppState, exportBackground: true, exportWithDarkMode: false },
          files,
          mimeType: "image/png",
          quality: 0.92,
        });
        preview = await new Promise<string>(resolve => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.readAsDataURL(blob);
        });
      } catch (ex) {
        console.warn("Whiteboard preview export failed:", ex);
      }

      // Dual-format: scene for re-editing, preview for artifact panel display.
      const content = JSON.stringify({ scene: { elements, appState: safeAppState }, preview });

      if (artifactId) {
        // Update existing artifact (PATCH sends `content`, server maps to `storage_ref`).
        const res = await authFetch(
          `${API_BASE}/sessions/${sessionId}/artifacts/${artifactId}`,
          {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content }),
          },
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      } else {
        // Create new artifact.
        const res = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: "Session Whiteboard",
            artifact_type: "whiteboard",
            content,
          }),
        });
        if (await maybeToastRateLimited(res)) return;
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const created: { id: string } = await res.json();
        setArtifactId(created.id);
      }

      setSavedAt(new Date());
      onSaveSuccess?.();
      toast.success(artifactId ? "Whiteboard updated" : "Whiteboard saved as artifact");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setSaveError(`Save failed: ${msg}`);
      toast.error(`Whiteboard save failed: ${msg}`);
      console.error("Whiteboard save error:", e);
    } finally {
      setSaving(false);
    }
  }, [sessionId, actorId, artifactId, onSaveSuccess]);

  // ── Render ───────────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <span className="text-xs text-muted">Loading whiteboard…</span>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Toolbar */}
      <div className="h-9 px-4 border-b border-border flex items-center justify-between shrink-0 bg-surface-1">
        <div className="flex items-center gap-2">
          <span className="text-2xs text-muted uppercase tracking-widest font-medium">
            Whiteboard
          </span>
          {artifactId && (
            <span className="text-2xs text-accent-blue bg-accent-blue/10 border border-accent-blue/20 px-1.5 py-0.5 rounded font-medium">
              artifact
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          {saveError && (
            <span className="text-2xs text-accent-red max-w-[200px] truncate" title={saveError}>
              {saveError}
            </span>
          )}
          {savedAt && !saving && !saveError && (
            <span className="text-2xs text-muted tabular-nums">
              Saved {savedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </span>
          )}
          <button
            onClick={saveAsArtifact}
            disabled={saving}
            className="text-xs px-3 py-1.5 rounded-lg bg-accent-blue/10 border border-accent-blue/25 text-accent-blue hover:bg-accent-blue/20 transition-colors font-medium disabled:opacity-50 shrink-0"
          >
            {saving ? "Saving…" : artifactId ? "Update Artifact" : "Save as Artifact"}
          </button>
        </div>
      </div>

      {/* Canvas */}
      <div className="flex-1 relative overflow-hidden">
        <Excalidraw
          excalidrawAPI={(api: ExcalidrawAPI) => { apiRef.current = api; }}
          initialData={initialData ?? undefined}
          theme="dark"
          UIOptions={{
            canvasActions: {
              saveToActiveFile: false,
              loadScene: false,
              export: false,
              toggleTheme: false,
            },
          }}
        />
      </div>
    </div>
  );
}
