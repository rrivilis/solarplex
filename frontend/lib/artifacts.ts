"use client";

// ── Artifact content fetch ───────────────────────────────────────────────────
//
// The WS snapshot only ever carries ArtifactSummary (id/name/type) — no
// content, so expanding an artifact needs this one extra round-trip.
// Content lives in the `storage_ref` column/field, not a field named
// "content" — see crates/db/src/artifacts.rs.

import { authFetch } from "./auth";
import { API_BASE } from "./env";

export interface ArtifactDetail {
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

export async function getArtifact(sessionId: string, artifactId: string): Promise<ArtifactDetail> {
  const res = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts/${artifactId}`);
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json();
}

export interface ImportArtifactResult {
  artifact: ArtifactDetail;
  /** True when this exact content was already imported here before — the
   *  server returned the existing copy instead of creating a duplicate. */
  alreadyImported: boolean;
}

/**
 * Publish/import a real independent copy of an artifact from a linked
 * session into `targetSessionId` — not a live reference (see
 * `sp session remote` for read-only cross-session viewing without copying).
 * The server auto-adds a context entry in the target recording provenance
 * (source session, original author, import receipt, content hash); the
 * caller doesn't need to do anything else to get that audit trail.
 *
 * Idempotent: re-importing the same source artifact content into the same
 * target session returns the existing copy (`alreadyImported: true`)
 * instead of spamming a duplicate — safe to call again on a retry.
 */
export async function importArtifact(
  targetSessionId: string,
  sourceSessionId: string,
  sourceArtifactId: string,
): Promise<ImportArtifactResult> {
  const res = await authFetch(`${API_BASE}/sessions/${targetSessionId}/artifacts/import`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      source_session_id: sourceSessionId,
      source_artifact_id: sourceArtifactId,
    }),
  });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  const data = await res.json();
  return { artifact: data.artifact ?? data, alreadyImported: data.already_imported === true };
}

/**
 * Whiteboard artifacts store dual-format JSON — `{ scene, preview }`, where
 * `preview` is a base64 PNG data URL rendered at save time (see
 * Whiteboard.tsx's saveAsArtifact). The `scene` half is raw Excalidraw
 * element/appState data, never meant for direct display — same rule
 * ArtifactsTab.tsx's ContentPreview already follows. Returns null for
 * legacy bare-scene artifacts (saved before the dual-format existed) or
 * anything that isn't valid JSON, so callers can fall back to a
 * "no preview yet" message instead of dumping raw scene data.
 */
export function whiteboardPreview(storageRef: string): string | null {
  try {
    const parsed = JSON.parse(storageRef);
    return typeof parsed.preview === "string" ? parsed.preview : null;
  } catch {
    return null;
  }
}
