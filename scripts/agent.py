#!/usr/bin/env python3
"""
Solarplex supervised agent — connect Claude or ChatGPT to a Solarplex session.

Every tool call the model wants to make is paused here and surfaced as an
approval request in the Solarplex UI.  A human approves or denies it from
the browser; the agent either executes the tool and continues, or receives
a "denied" message and decides what to do next.

──────────────────────────────────────────────────────────────────────────────
Setup (one-time):
    pip install anthropic openai websockets httpx

Usage:
    # Claude (Anthropic)
    ANTHROPIC_API_KEY=sk-ant-...
    SOLARPLEX_SESSION_ID=<paste session ID from the Solarplex UI>
    python agent.py "Write a Python script that prints prime numbers up to 100"

    # ChatGPT (OpenAI)
    OPENAI_API_KEY=sk-...
    SOLARPLEX_SESSION_ID=<paste session ID from the Solarplex UI>
    python agent.py --provider openai "List files in this directory and summarise them"

The session ID is shown in the URL when you open a session: /sessions/<id>
──────────────────────────────────────────────────────────────────────────────
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import uuid

import httpx
import websockets

# ── Configuration ─────────────────────────────────────────────────────────────

API_BASE   = os.getenv("SOLARPLEX_API", "http://localhost:8080/api")
WS_BASE    = os.getenv("SOLARPLEX_WS",  "ws://localhost:8080")
SESSION_ID = os.getenv("SOLARPLEX_SESSION_ID", "")

if not SESSION_ID:
    sys.exit(
        "Error: set the SOLARPLEX_SESSION_ID environment variable.\n"
        "You can copy the session ID from the URL bar when a session is open."
    )

# ── Tool definitions ──────────────────────────────────────────────────────────
#
# These are the tools the AI model may call.  Add more here as needed.
# The same spec is converted to Anthropic or OpenAI format below.

TOOLS_SPEC = [
    {
        "name": "bash",
        "description": (
            "Run a bash / shell command and return its stdout and stderr. "
            "Avoid long-running or interactive processes."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The shell command to execute."},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read and return the text contents of a file on disk.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative file path."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write text content to a file, creating or overwriting it.",
        "parameters": {
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "File path to write."},
                "content": {"type": "string", "description": "Text to write."},
            },
            "required": ["path", "content"],
        },
    },
]

# Anthropic format: `input_schema` instead of `parameters`
ANTHROPIC_TOOLS = [
    {"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
    for t in TOOLS_SPEC
]

# OpenAI format: wrapped in {"type": "function", "function": {...}}
OPENAI_TOOLS = [
    {"type": "function", "function": t}
    for t in TOOLS_SPEC
]


# ── Tool executor ─────────────────────────────────────────────────────────────

def execute_tool(name: str, args: dict) -> str:
    """Actually run an approved tool call and return its output as a string."""
    if name == "bash":
        try:
            result = subprocess.run(
                args["command"], shell=True,
                capture_output=True, text=True, timeout=30,
            )
            output = (result.stdout + result.stderr).strip()
            return output or "(no output)"
        except subprocess.TimeoutExpired:
            return "Error: command timed out after 30 s"
        except Exception as exc:
            return f"Error running command: {exc}"

    if name == "read_file":
        try:
            return open(args["path"]).read()
        except Exception as exc:
            return f"Error reading file: {exc}"

    if name == "write_file":
        try:
            with open(args["path"], "w") as fh:
                fh.write(args["content"])
            return f"Wrote {len(args['content'])} bytes to {args['path']}"
        except Exception as exc:
            return f"Error writing file: {exc}"

    return f"Unknown tool: {name}"


# ── Solarplex actor registration ──────────────────────────────────────────────

async def register_agent(provider: str, model: str) -> str:
    """
    Register a new agent actor with the Solarplex server and add it to the
    session as a member.  Returns the actor_id to use for the WebSocket.

    In v1 each run creates a fresh actor.  To reuse an actor across runs,
    store the returned actor_id somewhere and pass it via env var.
    """
    async with httpx.AsyncClient() as http:
        # Step 1: create a global agent actor entry.
        r = await http.post(
            f"{API_BASE}/actors/agents",
            json={"name": f"{provider}-agent", "provider": provider, "model": model},
        )
        r.raise_for_status()
        actor_id: str = r.json()["id"]
        print(f"[solarplex] registered agent actor: {actor_id}")

        # Step 2: add that actor to the session.
        r2 = await http.post(
            f"{API_BASE}/sessions/{SESSION_ID}/members",
            json={"actor_id": actor_id, "role": "agent"},
        )
        if r2.status_code == 201:
            print(f"[solarplex] joined session {SESSION_ID}")
        elif r2.status_code in (200, 409):
            print(f"[solarplex] already a member of session {SESSION_ID}")
        else:
            print(f"[solarplex] warning: add_member returned {r2.status_code}: {r2.text}")

        return actor_id


# ── WebSocket approval bridge ─────────────────────────────────────────────────

async def run_agent(provider: str, model: str, task: str) -> None:
    actor_id = await register_agent(provider, model)

    ws_url = f"{WS_BASE}/sessions/{SESSION_ID}/stream?actor_id={actor_id}"
    print(f"[solarplex] connecting → {ws_url}\n")

    async with websockets.connect(ws_url) as ws:
        # pending[approval_id] = Future that resolves with "granted" | "denied"
        pending: dict[str, asyncio.Future] = {}
        loop = asyncio.get_event_loop()

        async def ws_reader() -> None:
            """Drain incoming WS frames; resolve approval futures on resolution."""
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if msg.get("type") == "approval.resolved":
                    aid = msg.get("approval_id", "")
                    if aid in pending and not pending[aid].done():
                        pending[aid].set_result(msg.get("decision", "denied"))

        reader_task = asyncio.create_task(ws_reader())

        async def request_approval(tool_name: str, args: dict) -> str:
            """
            Send an approval.request to the session and block until a human
            approves or denies it (or 5 min timeout → auto-deny).
            Returns "granted" or "denied".
            """
            approval_id = str(uuid.uuid4())
            fut: asyncio.Future = loop.create_future()
            pending[approval_id] = fut

            await ws.send(json.dumps({
                "protocol_version": 1,
                "id": str(uuid.uuid4()),
                "type": "approval.request",
                "session_id": SESSION_ID,
                "actor_id": actor_id,
                "approval_id": approval_id,
                "tool_call": {"tool": tool_name, "args": args},
            }))

            # Surface which tool is waiting so the human has context in the UI
            print(f"  [⏳ waiting] '{tool_name}' — approve or deny it in the Solarplex UI")

            try:
                decision = await asyncio.wait_for(fut, timeout=300)
                return decision
            except asyncio.TimeoutError:
                pending.pop(approval_id, None)
                print(f"  [⌛ timeout] '{tool_name}' auto-denied after 5 min")
                return "denied"

        # ── Run the right provider's agent loop ────────────────────────────────
        try:
            if provider == "anthropic":
                await _claude_loop(task, request_approval)
            elif provider == "openai":
                await _openai_loop(task, request_approval)
            else:
                raise ValueError(f"Unknown provider: {provider}")
        finally:
            reader_task.cancel()


# ── Claude agent loop ─────────────────────────────────────────────────────────

async def _claude_loop(task: str, request_approval) -> None:
    try:
        import anthropic
    except ImportError:
        sys.exit("Install the Anthropic SDK:  pip install anthropic")

    client = anthropic.AsyncAnthropic()
    messages = [{"role": "user", "content": task}]

    print(f"[claude] ▶  {task}\n")

    while True:
        resp = await client.messages.create(
            model="claude-opus-4-5",
            max_tokens=4096,
            tools=ANTHROPIC_TOOLS,
            messages=messages,
        )

        if resp.stop_reason == "end_turn":
            text = next((b.text for b in resp.content if hasattr(b, "text")), "(no text)")
            print(f"\n[claude] ✅  {text}")
            break

        if resp.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": resp.content})
            tool_results = []

            for block in resp.content:
                if block.type != "tool_use":
                    continue

                args_str = json.dumps(block.input, ensure_ascii=False)
                print(f"\n[claude] 🔧  {block.name}({args_str[:120]}{'…' if len(args_str) > 120 else ''})")

                decision = await request_approval(block.name, block.input)
                print(f"  [solarplex] → {decision}")

                if decision == "granted":
                    result = execute_tool(block.name, block.input)
                    preview = result[:200] + "…" if len(result) > 200 else result
                    print(f"  [result]    {preview}")
                else:
                    result = f"Tool '{block.name}' was denied by a human supervisor in Solarplex."

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })

            messages.append({"role": "user", "content": tool_results})


# ── OpenAI agent loop ─────────────────────────────────────────────────────────

async def _openai_loop(task: str, request_approval) -> None:
    try:
        from openai import AsyncOpenAI
    except ImportError:
        sys.exit("Install the OpenAI SDK:  pip install openai")

    client = AsyncOpenAI()
    messages = [{"role": "user", "content": task}]

    print(f"[gpt] ▶  {task}\n")

    while True:
        resp = await client.chat.completions.create(
            model="gpt-4o",
            tools=OPENAI_TOOLS,
            messages=messages,
        )
        choice = resp.choices[0]

        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            messages.append(choice.message)

            for tc in choice.message.tool_calls:
                args = json.loads(tc.function.arguments)
                args_str = json.dumps(args, ensure_ascii=False)
                print(f"\n[gpt] 🔧  {tc.function.name}({args_str[:120]}{'…' if len(args_str) > 120 else ''})")

                decision = await request_approval(tc.function.name, args)
                print(f"  [solarplex] → {decision}")

                if decision == "granted":
                    result = execute_tool(tc.function.name, args)
                    preview = result[:200] + "…" if len(result) > 200 else result
                    print(f"  [result]    {preview}")
                else:
                    result = f"Tool '{tc.function.name}' was denied by a human supervisor in Solarplex."

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

        else:
            text = choice.message.content or "(no text)"
            print(f"\n[gpt] ✅  {text}")
            break


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a Claude or ChatGPT agent with Solarplex human approval.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--provider", choices=["anthropic", "openai"], default="anthropic",
        help="AI provider to use (default: anthropic / Claude)",
    )
    parser.add_argument(
        "--model", default="",
        help="Override the default model (claude-opus-4-5 or gpt-4o)",
    )
    parser.add_argument(
        "task", nargs="*",
        default=["List the files in the current directory and summarise what you find."],
    )
    args = parser.parse_args()

    model = args.model or ("claude-opus-4-5" if args.provider == "anthropic" else "gpt-4o")
    task  = " ".join(args.task)

    asyncio.run(run_agent(args.provider, model, task))


if __name__ == "__main__":
    main()
