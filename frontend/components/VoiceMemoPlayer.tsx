"use client";

import { useEffect, useRef, useState } from "react";
import WaveSurfer from "wavesurfer.js";
import { API_BASE } from "@/lib/env";
import { authFetch } from "@/lib/auth";

interface Props {
  sessionId: string;
  artifactId: string;
}

/** Convert a base64 data-URI to a Blob URL WaveSurfer can load. */
function dataURItoObjectURL(dataURI: string): string {
  const [header, b64] = dataURI.split(",");
  const mime = header.match(/:(.*?);/)?.[1] ?? "audio/webm";
  const binary = atob(b64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  const blob = new Blob([buf], { type: mime });
  return URL.createObjectURL(blob);
}

export default function VoiceMemoPlayer({ sessionId, artifactId }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WaveSurfer | null>(null);
  const objectURLRef = useRef<string | null>(null);

  const [playing, setPlaying] = useState(false);
  const [duration, setDuration] = useState<number | null>(null);
  const [currentTime, setCurrentTime] = useState(0);
  const [loading, setLoading] = useState(true);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    if (!containerRef.current) return;
    let cancelled = false;

    async function init() {
      try {
        const res = await authFetch(
          `${API_BASE}/sessions/${sessionId}/artifacts/${artifactId}`,
        );
        if (!res.ok || cancelled) return;
        const data = await res.json();
        const src: string = data.storage_ref;
        if (!src || cancelled || !containerRef.current) return;

        // Convert data-URI → object URL so WaveSurfer can fetch it.
        const objURL = dataURItoObjectURL(src);
        objectURLRef.current = objURL;

        const ws = WaveSurfer.create({
          container: containerRef.current!,
          waveColor: "rgba(99,102,241,0.45)",
          progressColor: "rgb(59,130,246)",
          cursorColor: "transparent",
          height: 28,
          barWidth: 2,
          barGap: 1,
          barRadius: 2,
          normalize: true,
          url: objURL,
        });
        wsRef.current = ws;

        ws.on("ready", (dur) => {
          if (cancelled) return;
          setDuration(dur);
          setLoading(false);
        });
        ws.on("play",   () => { if (!cancelled) setPlaying(true); });
        ws.on("pause",  () => { if (!cancelled) setPlaying(false); });
        ws.on("finish", () => { if (!cancelled) setPlaying(false); });
        ws.on("timeupdate", (t) => { if (!cancelled) setCurrentTime(t); });
        ws.on("error",  () => { if (!cancelled) { setErrored(true); setLoading(false); } });
      } catch {
        if (!cancelled) { setErrored(true); setLoading(false); }
      }
    }

    init();

    return () => {
      cancelled = true;
      wsRef.current?.destroy();
      wsRef.current = null;
      if (objectURLRef.current) {
        URL.revokeObjectURL(objectURLRef.current);
        objectURLRef.current = null;
      }
    };
  }, [sessionId, artifactId]);

  function fmt(s: number) {
    const m = Math.floor(s / 60);
    const sec = Math.floor(s % 60);
    return `${m}:${sec.toString().padStart(2, "0")}`;
  }

  return (
    <div className="flex items-center gap-2.5 mt-1.5 bg-surface-2 border border-border rounded-xl px-3 py-2 max-w-[280px] group">
      {/* Play/pause */}
      <button
        onClick={() => wsRef.current?.playPause()}
        disabled={loading || errored}
        className="w-7 h-7 flex items-center justify-center rounded-full bg-accent-blue/15 text-accent-blue hover:bg-accent-blue/30 transition-colors disabled:opacity-30 shrink-0"
        aria-label={playing ? "Pause" : "Play"}
      >
        {playing ? (
          <svg width="9" height="9" viewBox="0 0 9 9" fill="currentColor">
            <rect x="0.5" y="0.5" width="3" height="8" rx="1" />
            <rect x="5.5" y="0.5" width="3" height="8" rx="1" />
          </svg>
        ) : (
          <svg width="9" height="9" viewBox="0 0 9 9" fill="currentColor">
            <path d="M1 0.5l8 4-8 4V0.5z" />
          </svg>
        )}
      </button>

      {/* Waveform + time */}
      <div className="flex-1 min-w-0">
        {loading && !errored && (
          <span className="text-2xs text-muted">Loading…</span>
        )}
        {errored && (
          <span className="text-2xs text-accent-red">Unavailable</span>
        )}
        {/* WaveSurfer mounts here — always rendered so the ref is available */}
        <div ref={containerRef} className={loading || errored ? "hidden" : ""} />
      </div>

      {/* Elapsed / duration */}
      {!loading && !errored && (
        <span className="text-2xs text-muted font-mono shrink-0 tabular-nums">
          {fmt(playing ? currentTime : (duration ?? 0))}
        </span>
      )}
    </div>
  );
}
