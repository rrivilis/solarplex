"use client";

import { useEffect, useRef, useState } from "react";
import { useAutoAnimate } from "@formkit/auto-animate/react";
import RelativeTime from "@/components/RelativeTime";
import { toast } from "sonner";
import { Tooltip, TooltipContent, TooltipTrigger } from "@radix-ui/react-tooltip";

// Lexical core
import { LexicalComposer } from "@lexical/react/LexicalComposer";
import { PlainTextPlugin } from "@lexical/react/LexicalPlainTextPlugin";
import { ContentEditable } from "@lexical/react/LexicalContentEditable";
import { HistoryPlugin } from "@lexical/react/LexicalHistoryPlugin";
import { OnChangePlugin } from "@lexical/react/LexicalOnChangePlugin";
import { useLexicalComposerContext } from "@lexical/react/LexicalComposerContext";
// eslint-disable-next-line @typescript-eslint/no-require-imports
const LexicalErrorBoundary = require("@lexical/react/LexicalErrorBoundary").default;
import {
  $getRoot,
  $createParagraphNode,
  $createTextNode,
  KEY_ENTER_COMMAND,
  COMMAND_PRIORITY_HIGH,
  COMMAND_PRIORITY_CRITICAL,
  createCommand,
  EditorState,
  type LexicalEditor,
} from "lexical";

import { MessageEntry, WsEnvelope } from "@/lib/types";
import MessageBody from "@/components/MessageBody";
import { API_BASE } from "@/lib/env";
import { authFetch, maybeToastRateLimited } from "@/lib/auth";

// ── Lexical: custom send command ──────────────────────────────────────────────
const SEND_MESSAGE_COMMAND = createCommand<void>("SEND_MESSAGE");

// ── Lexical: send plugin — handles Enter key + SEND_MESSAGE_COMMAND ───────────
function SendPlugin({ onSend }: { onSend: (text: string) => void }) {
  const [editor] = useLexicalComposerContext();
  // Stable ref so the effect never needs to re-register when onSend changes identity.
  const onSendRef = useRef(onSend);
  onSendRef.current = onSend;

  useEffect(() => {
    function clearEditor() {
      editor.update(() => {
        const root = $getRoot();
        root.clear();
        root.append($createParagraphNode());
      });
    }

    function doSend() {
      let text = "";
      editor.getEditorState().read(() => { text = $getRoot().getTextContent().trim(); });
      if (text) { onSendRef.current(text); clearEditor(); }
    }

    const removeEnter = editor.registerCommand(
      KEY_ENTER_COMMAND,
      (e: KeyboardEvent | null) => {
        if (e?.shiftKey) return false;   // Shift+Enter → newline passthrough
        e?.preventDefault();
        doSend();
        return true;
      },
      COMMAND_PRIORITY_HIGH,
    );

    const removeSend = editor.registerCommand(
      SEND_MESSAGE_COMMAND,
      () => { doSend(); return true; },
      COMMAND_PRIORITY_HIGH,
    );

    return () => { removeEnter(); removeSend(); };
  }, [editor]);

  return null;
}

// ── Lexical: editable toggle ──────────────────────────────────────────────────
function EditablePlugin({ editable }: { editable: boolean }) {
  const [editor] = useLexicalComposerContext();
  useEffect(() => { editor.setEditable(editable); }, [editor, editable]);
  return null;
}

// ── Lexical: send button (needs editor context) ───────────────────────────────
function SendButton({ isEmpty, disabled }: { isEmpty: boolean; disabled: boolean }) {
  const [editor] = useLexicalComposerContext();
  return (
    <button
      onClick={() => editor.dispatchCommand(SEND_MESSAGE_COMMAND, undefined)}
      disabled={isEmpty || disabled}
      aria-label="Send message"
      className="text-2xs text-muted hover:text-accent-blue disabled:opacity-30 transition-colors shrink-0 p-[5px]"
    >
      ↵
    </button>
  );
}

// ── @ Mention plugin ──────────────────────────────────────────────────────────

interface MentionState {
  query: string;          // text after @
  offset: number;         // char offset where @ starts in the full text
}

/** Watches editor text for an active @query and calls back with match info. */
function MentionPlugin({
  members,
  onMention,
}: {
  members: string[];
  onMention: (state: MentionState | null) => void;
}) {
  const [editor] = useLexicalComposerContext();
  const onMentionRef = useRef(onMention);
  onMentionRef.current = onMention;

  useEffect(() => {
    return editor.registerUpdateListener(({ editorState }) => {
      editorState.read(() => {
        const text = $getRoot().getTextContent();
        // Find the last @ that hasn't been followed by a space
        const match = text.match(/@([a-zA-Z0-9_-]*)$/);
        if (match && members.length > 0) {
          onMentionRef.current({ query: match[1], offset: text.lastIndexOf("@") });
        } else {
          onMentionRef.current(null);
        }
      });
    });
  }, [editor, members]);

  return null;
}

/** Replaces the trailing @query with @selected in the editor. */
function insertMention(editor: LexicalEditor, actorId: string, offset: number) {
  editor.update(() => {
    const root = $getRoot();
    const fullText = root.getTextContent();
    const before = fullText.slice(0, offset);
    const replaced = fullText.slice(offset).replace(/@[a-zA-Z0-9_-]*$/, `@${actorId} `);
    root.clear();
    const para = $createParagraphNode();
    para.append($createTextNode(before + replaced));
    root.append(para);
    root.getLastDescendant()?.selectEnd();
  });
}

// ── Presence events ───────────────────────────────────────────────────────────
const PRESENCE_EVENTS = new Set(["actor.joined", "actor.detached", "ownership.transferred"]);

function presenceText(event: WsEnvelope, actorNames: Record<string, string> = {}): string {
  const resolve = (id: unknown): string =>
    typeof id === "string" ? (actorNames[id] ?? id) : String(id ?? "");
  switch (event.type) {
    case "actor.joined":   return `${resolve(event.actor)} joined the session`;
    case "actor.detached": return `${resolve(event.actor)} left the session`;
    case "ownership.transferred": {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const p = event.payload as any;
      return `Ownership transferred from ${resolve(p?.from)} to ${resolve(p?.to)}`;
    }
    default: return "";
  }
}

// ── Stream builder ────────────────────────────────────────────────────────────
type StreamItem =
  | { kind: "message"; entry: MessageEntry }
  | { kind: "presence"; event: WsEnvelope };

function buildStream(messages: MessageEntry[], events: WsEnvelope[]): StreamItem[] {
  const items: StreamItem[] = [
    ...messages.map(m => ({ kind: "message" as const, entry: m })),
    ...events.filter(e => PRESENCE_EVENTS.has(e.type)).map(e => ({ kind: "presence" as const, event: e })),
  ];
  items.sort((a, b) => {
    const ta = a.kind === "message" ? a.entry.timestamp : (a.event.timestamp ?? "");
    const tb = b.kind === "message" ? b.entry.timestamp : (b.event.timestamp ?? "");
    return ta < tb ? -1 : ta > tb ? 1 : 0;
  });
  return items;
}

// ── Avatar ────────────────────────────────────────────────────────────────────
function Avatar({ actor, self }: { actor: string; self: boolean }) {
  return (
    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-2xs font-semibold shrink-0 select-none ${
      // text-accent-blue on bg-accent-blue/25 measured 3.4-4.0:1 depending on
      // what's composited underneath (below the 4.5:1 AA floor) — text-primary
      // clears 8.3-9.6:1 against the same range regardless of composite.
      self ? "bg-accent-blue/25 text-primary" : "bg-surface-3 text-subtle"
    }`}>
      {actor.slice(0, 2).toUpperCase()}
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtDuration(secs: number) {
  return `${Math.floor(secs / 60)}:${(secs % 60).toString().padStart(2, "0")}`;
}

const TEXT_EXTS = new Set([".txt", ".md", ".json", ".csv", ".yaml", ".yml", ".xml", ".html", ".css", ".js", ".ts"]);
function isTextFile(file: File) {
  if (file.type.startsWith("text/")) return true;
  return TEXT_EXTS.has(file.name.substring(file.name.lastIndexOf(".")).toLowerCase());
}

function readAsDataURL(blob: Blob): Promise<string> {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload  = () => res(r.result as string);
    r.onerror = rej;
    r.readAsDataURL(blob);
  });
}

// ── Mention picker (must be inside LexicalComposer for editor context) ────────
function MentionPickerPortal({
  matches,
  query,
  offset,
  onSelect,
  onDismiss,
}: {
  matches: string[];
  query: string;
  offset: number;
  onSelect: (editor: LexicalEditor, id: string) => void;
  onDismiss: () => void;
}) {
  const [editor] = useLexicalComposerContext();
  const [focused, setFocused] = useState(0);

  useEffect(() => { setFocused(0); }, [matches.join(",")]);

  // Intercept Enter at CRITICAL priority — higher than SendPlugin's HIGH,
  // so this handler always runs first and can return true before send fires.
  useEffect(() => {
    return editor.registerCommand(
      KEY_ENTER_COMMAND,
      (e) => {
        e?.preventDefault();
        onSelect(editor, matches[focused]);
        return true; // consumed — command stops here, SendPlugin never sees it
      },
      COMMAND_PRIORITY_CRITICAL,
    );
  }, [editor, matches, focused, onSelect]);

  // Arrow/Escape via native capture (Lexical doesn't dispatch commands for these)
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!matches.length) return;
      if (e.key === "ArrowDown") { e.preventDefault(); e.stopPropagation(); setFocused(f => (f + 1) % matches.length); }
      if (e.key === "ArrowUp")   { e.preventDefault(); e.stopPropagation(); setFocused(f => (f - 1 + matches.length) % matches.length); }
      if (e.key === "Tab")       { e.preventDefault(); e.stopPropagation(); onSelect(editor, matches[focused]); }
      if (e.key === "Escape")    { e.stopPropagation(); onDismiss(); }
    }
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [editor, matches, focused, onSelect, onDismiss]);

  return (
    <div
      role="listbox"
      aria-label="Mention suggestions"
      className="absolute bottom-full mb-1 left-0 right-0 bg-surface-2 border border-border rounded-lg shadow-elevation-float overflow-hidden z-50"
    >
      {matches.map((id, i) => (
        <button
          key={id}
          role="option"
          aria-selected={i === focused}
          onMouseDown={e => { e.preventDefault(); onSelect(editor, id); }}
          className={`w-full flex items-center gap-2 px-3 py-1.5 text-xs transition-colors ${
            i === focused ? "bg-surface-3 text-primary" : "text-subtle hover:bg-surface-3 hover:text-primary"
          }`}
        >
          <span className="w-5 h-5 rounded-full bg-surface-3 flex items-center justify-center text-2xs font-semibold text-muted shrink-0 select-none">
            {id.slice(0, 2).toUpperCase()}
          </span>
          <span className="font-medium">
            <span className="text-muted">@</span>
            {query
              ? id.split(new RegExp(`(${query})`, "i")).map((part, pi) =>
                  part.toLowerCase() === query.toLowerCase()
                    ? <mark key={pi} className="bg-transparent text-accent-blue font-semibold">{part}</mark>
                    : part
                )
              : id}
          </span>
        </button>
      ))}
      <div className="px-3 py-1 border-t border-border/50 flex items-center gap-2">
        <span className="text-2xs text-muted">↑↓ navigate · Enter select · Esc dismiss</span>
      </div>
      {/* Focus stays in the text editor itself (Lexical intercepts arrow
          keys at the document level — see the keydown effect above), so
          there's no DOM focus to move onto these options for a screen
          reader to follow. This announces the highlight change instead of
          wiring aria-activedescendant across the editor/portal boundary,
          which would mean lifting `focused` state into the ContentEditable
          plugin tree in the parent component — a materially bigger change
          for the same result. */}
      <span className="sr-only" role="status" aria-live="polite">
        {matches.length > 0 && `${matches[focused]}, ${focused + 1} of ${matches.length}`}
      </span>
    </div>
  );
}

// ── Props ─────────────────────────────────────────────────────────────────────
interface Props {
  sessionId: string;
  messages: MessageEntry[];
  events: WsEnvelope[];
  actorId: string;
  /** actor_id -> display name, derived from the session snapshot. Events and
   *  messages correctly keep storing the raw id; this is resolved at
   *  display time so a rename shows up retroactively across all history. */
  actorNames?: Record<string, string>;
  members?: string[];     // actor IDs available for @ mention
  onSend: (content: string) => void;
  onArtifactCreated?: () => void;
}

// ── Lexical editor config (stable — defined outside component) ────────────────
const editorConfig = {
  namespace: "solarplex-messages",
  theme: {},
  onError: (e: Error) => console.error("[Lexical]", e),
};

// ── Component ─────────────────────────────────────────────────────────────────
export default function Messages({ sessionId, messages, events, actorId, actorNames = {}, members = [], onSend, onArtifactCreated }: Props) {
  const stream    = buildStream(messages, events);
  const bottomRef = useRef<HTMLDivElement>(null);
  const fileRef   = useRef<HTMLInputElement>(null);
  const mediaRef  = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const timerRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const recSecsRef = useRef(0);

  const [streamRef]        = useAutoAnimate<HTMLDivElement>();

  const [mentionState,   setMentionState]   = useState<MentionState | null>(null);
  const [recording,      setRecording]      = useState(false);
  const [recSeconds,     setRecSeconds]     = useState(0);
  const [uploadingFile,  setUploadingFile]  = useState(false);
  const [uploadingVoice, setUploadingVoice] = useState(false);
  const [uploadError,    setUploadError]    = useState<string | null>(null);
  const [editorEmpty,    setEditorEmpty]    = useState(true);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [stream.length]);

  // ── Screen-reader announcement for new messages ─────────────────────────
  // Nothing in this view was in a live region before this — a screen
  // reader user had no way to know a new message arrived at all short of
  // re-navigating into the list manually. Announces only genuine live
  // arrivals (not the initial history load on mount, not the sender's own
  // message echoing back to them) — the visually-hidden region carries
  // just the one new message, never the whole list, or every re-render
  // would re-read the entire conversation from the top.
  const prevMessageCountRef = useRef<number | null>(null);
  const [announcement, setAnnouncement] = useState("");
  useEffect(() => {
    const prevCount = prevMessageCountRef.current;
    prevMessageCountRef.current = messages.length;
    if (prevCount === null || messages.length <= prevCount) return;
    const latest = messages[messages.length - 1];
    if (!latest || latest.actor === actorId) return;
    const name = actorNames[latest.actor] ?? latest.actor;
    setAnnouncement(`New message from ${name}: ${latest.content.slice(0, 120)}`);
  }, [messages, actorId, actorNames]);

  // Recording timer
  useEffect(() => {
    if (recording) {
      recSecsRef.current = 0;
      setRecSeconds(0);
      timerRef.current = setInterval(() => { recSecsRef.current += 1; setRecSeconds(recSecsRef.current); }, 1000);
    } else {
      if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [recording]);

  // Track editor empty state for send button
  function handleEditorChange(state: EditorState) {
    state.read(() => setEditorEmpty($getRoot().getTextContent().trim().length === 0));
  }

  // ── File upload ─────────────────────────────────────────────────────────────
  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (fileRef.current) fileRef.current.value = "";

    if (file.size > 3 * 1024 * 1024) { setUploadError("File exceeds 3 MB limit."); toast.error("File exceeds 3 MB limit"); return; }

    setUploadingFile(true);
    setUploadError(null);
    const uploadToast = toast.loading(`Uploading ${file.name}…`);
    try {
      const content = isTextFile(file) ? await file.text() : await readAsDataURL(file);
      const res = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: file.name, artifact_type: file.type || "file", content }),
      });
      if (await maybeToastRateLimited(res, uploadToast)) return;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const artifact: { id: string } = await res.json();
      onSend(`📎 ${file.name} [artifact:${artifact.id}]`);
      onArtifactCreated?.();
      toast.success(`${file.name} uploaded`, { id: uploadToast });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[Messages] file upload failed:", msg, err);
      setUploadError(`Upload failed: ${msg}`);
      toast.error(`Upload failed: ${msg}`, { id: uploadToast });
    } finally { setUploadingFile(false); }
  }

  // ── Voice recording ─────────────────────────────────────────────────────────
  async function startRecording() {
    setUploadError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mimeType = MediaRecorder.isTypeSupported("audio/webm;codecs=opus")
        ? "audio/webm;codecs=opus"
        : MediaRecorder.isTypeSupported("audio/webm") ? "audio/webm" : "";
      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
      chunksRef.current = [];
      recorder.ondataavailable = (e) => { if (e.data.size > 0) chunksRef.current.push(e.data); };
      recorder.onstop = async () => {
        stream.getTracks().forEach(t => t.stop());
        await uploadVoiceMemo(new Blob(chunksRef.current, { type: mimeType || "audio/webm" }), recSecsRef.current);
      };
      mediaRef.current = recorder;
      recorder.start(100);
      setRecording(true);
    } catch { setUploadError("Microphone access denied."); }
  }

  function stopRecording() {
    mediaRef.current?.stop();
    mediaRef.current = null;
    setRecording(false);
  }

  async function uploadVoiceMemo(blob: Blob, dur: number) {
    setUploadingVoice(true);
    setUploadError(null);
    const voiceToast = toast.loading("Saving voice memo…");
    try {
      const content = await readAsDataURL(blob);
      const name    = `Voice memo ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
      const res = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, artifact_type: "voice_memo", content }),
      });
      if (await maybeToastRateLimited(res, voiceToast)) return;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const artifact: { id: string } = await res.json();
      onSend(`🎙️ Voice memo · ${fmtDuration(dur)} [artifact:${artifact.id}]`);
      onArtifactCreated?.();
      toast.success("Voice memo saved", { id: voiceToast });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[Messages] voice memo upload failed:", msg, err);
      setUploadError(`Voice memo upload failed: ${msg}`);
      toast.error(`Voice memo upload failed: ${msg}`, { id: voiceToast });
    } finally { setUploadingVoice(false); }
  }

  const busy = uploadingFile || uploadingVoice;

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full">
      <div aria-live="polite" role="status" className="sr-only">{announcement}</div>

      {/* Stream */}
      <div className="flex-1 overflow-y-auto px-5 py-4">
        {stream.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2 text-center">
            <p className="text-xs text-muted">No messages yet</p>
            <p className="text-2xs text-muted">Start the conversation — others will see it when they attach</p>
          </div>
        ) : (
          <div ref={streamRef} className="space-y-0.5">
            {stream.map((item, i) => {
              if (item.kind === "presence") {
                return (
                  <div key={item.event.id} className="flex items-center gap-3 py-1.5 my-1">
                    <div className="flex-1 h-px bg-border" />
                    <span className="text-2xs text-muted shrink-0 italic">{presenceText(item.event, actorNames)}</span>
                    <div className="flex-1 h-px bg-border" />
                  </div>
                );
              }

              const { entry } = item;
              const isSelf    = entry.actor === actorId;
              const prev      = stream[i - 1];
              const prevActor = prev?.kind === "message" ? prev.entry.actor : null;
              const isGrouped = prevActor === entry.actor;

              return (
                <div key={entry.id} className={`flex gap-2.5 ${isGrouped ? "mt-0.5" : "mt-3"} group`}>
                  <div className="w-6 shrink-0 mt-0.5">
                    {!isGrouped && <Avatar actor={actorNames[entry.actor] ?? entry.actor} self={isSelf} />}
                  </div>
                  <div className="flex-1 min-w-0">
                    {!isGrouped && (
                      <div className="flex items-baseline gap-2 mb-0.5">
                        <span className={`text-xs font-semibold ${isSelf ? "text-accent-blue" : "text-primary"}`}>
                          {actorNames[entry.actor] ?? entry.actor}
                        </span>
                        <RelativeTime
                          date={entry.timestamp}
                          className="text-2xs text-muted"
                        />
                      </div>
                    )}
                    <MessageBody sessionId={sessionId} content={entry.content} />
                  </div>
                </div>
              );
            })}
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input bar */}
      <div className="shrink-0 border-t border-border px-4 py-3">

        {/* Error banner */}
        {uploadError && (
          <div className="flex items-center justify-between mb-2 px-3 py-1.5 bg-accent-red/10 border border-accent-red/20 rounded-lg">
            <span className="text-2xs text-accent-red">{uploadError}</span>
            <button onClick={() => setUploadError(null)} aria-label="Dismiss error" className="text-2xs text-accent-red/60 hover:text-accent-red ml-2">✕</button>
          </div>
        )}

        <LexicalComposer initialConfig={editorConfig}>
          <div className={`relative flex items-end gap-2 bg-surface-2 border rounded-lg px-3 py-2 transition-all ${
            recording
              ? "border-accent-red/50 ring-1 ring-accent-red/20"
              : "border-border focus-within:border-accent-blue/40 focus-within:ring-1 focus-within:ring-accent-blue/15"
          }`}>
            <Avatar actor={actorNames[actorId] ?? actorId} self={true} />

            {/* Editor OR recording indicator */}
            {recording ? (
              <div className="flex-1 flex items-center gap-2 py-0.5 min-h-[20px]">
                <span className="w-2 h-2 rounded-full bg-accent-red shrink-0 animate-pulse" />
                <span className="text-xs font-mono text-accent-red tabular-nums">{fmtDuration(recSeconds)}</span>
                <span className="text-xs text-muted">Recording voice memo…</span>
              </div>
            ) : (
              // tabIndex: same fix as StatusPanel's scrollable content div —
              // axe's scrollable-region-focusable doesn't credit the nested
              // Lexical contenteditable as making this ancestor reachable,
              // so the wrapper needs its own explicit stop in the tab order.
              // Only actually scrolls once wrapped placeholder/typed text
              // exceeds max-h-32, e.g. at narrow (320px) viewports.
              <div tabIndex={0} className="relative flex-1 min-h-[20px] max-h-32 overflow-y-auto">
                <PlainTextPlugin
                  contentEditable={
                    <ContentEditable
                      aria-label="Message"
                      className="text-xs text-primary outline-none leading-relaxed py-0.5 min-h-[20px] disabled:opacity-40"
                    />
                  }
                  placeholder={
                    <div className="absolute top-0.5 left-0 text-xs text-muted pointer-events-none select-none">
                      Message the session… (Enter to send, Shift+Enter for newline)
                    </div>
                  }
                  ErrorBoundary={LexicalErrorBoundary}
                />
              </div>
            )}

            {/* Clip */}
            {!recording && (
              <>
                <input ref={fileRef} type="file" className="hidden" onChange={handleFileChange} />
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      onClick={() => fileRef.current?.click()}
                      disabled={busy}
                      aria-label="Attach file as artifact"
                      className="text-muted hover:text-subtle transition-colors shrink-0 disabled:opacity-30 p-[5px]"
                    >
                      {uploadingFile ? <span className="text-2xs">…</span> : (
                        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M13.5 7.5l-6.5 6.5a4 4 0 01-5.66-5.66l7-7a2.5 2.5 0 013.54 3.54L5 11.5a1 1 0 01-1.41-1.41L10 4" />
                        </svg>
                      )}
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="top" className="text-2xs bg-surface-3 border border-border text-subtle px-2 py-1 rounded-lg shadow-elevation-float">
                    Attach file as artifact
                  </TooltipContent>
                </Tooltip>
              </>
            )}

            {/* Mic */}
            <Tooltip>
              <TooltipTrigger asChild>
            <button
              onClick={recording ? stopRecording : startRecording}
              disabled={busy && !recording}
              aria-label={recording ? "Stop recording" : "Record voice memo"}
              className={`transition-colors shrink-0 p-[5px] disabled:opacity-30 ${
                recording ? "text-accent-red hover:text-accent-red/70" : "text-muted hover:text-subtle"
              }`}
            >
              {uploadingVoice ? <span className="text-2xs">…</span>
                : recording ? (
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
                    <rect x="2" y="2" width="10" height="10" rx="1.5" />
                  </svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="5" y="1" width="6" height="9" rx="3" />
                    <path d="M2 8a6 6 0 0012 0" />
                    <line x1="8" y1="14" x2="8" y2="16" />
                    <line x1="5.5" y1="16" x2="10.5" y2="16" />
                  </svg>
                )}
            </button>
              </TooltipTrigger>
              <TooltipContent side="top" className="text-2xs bg-surface-3 border border-border text-subtle px-2 py-1 rounded-lg shadow-elevation-float">
                {recording ? "Stop recording" : "Record voice memo"}
              </TooltipContent>
            </Tooltip>

            {/* Send — must be inside LexicalComposer to access context */}
            {!recording && <SendButton isEmpty={editorEmpty} disabled={busy} />}

            {/* @ Mention picker — absolute, anchored to this relative container */}
            {mentionState && members.length > 0 && (() => {
              const q = mentionState.query.toLowerCase();
              const matches = members
                .filter(m => m !== actorId && m.toLowerCase().includes(q))
                .slice(0, 6);
              if (matches.length === 0) return null;
              return (
                <MentionPickerPortal
                  matches={matches}
                  query={mentionState.query}
                  offset={mentionState.offset}
                  onSelect={(editor, id) => {
                    insertMention(editor, id, mentionState.offset);
                    setMentionState(null);
                  }}
                  onDismiss={() => setMentionState(null)}
                />
              );
            })()}
          </div>

          {/* Lexical plugins */}
          <MentionPlugin members={members} onMention={setMentionState} />
          <SendPlugin onSend={onSend} />
          <HistoryPlugin />
          <EditablePlugin editable={!recording && !busy} />
          <OnChangePlugin onChange={handleEditorChange} />
        </LexicalComposer>

        <p className="text-2xs text-muted mt-1.5 ml-1">
          {recording
            ? "Click ⏹ to stop and save your voice memo"
            : "Visible to all session members · 📎 attach files · 🎙️ voice memos"}
        </p>
      </div>
    </div>
  );
}
