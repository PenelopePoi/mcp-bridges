#!/usr/bin/env python3
"""
MCP Bridge: Suno — AI Music Generation via MCP protocol.
Uses the gcui-art/suno-api compatible REST endpoints.

Supports two modes:
  1. Self-hosted: Run gcui-art/suno-api locally → set SUNO_API_URL
  2. Proxy service: Use a third-party Suno API proxy → set SUNO_API_URL + SUNO_API_KEY

Prerequisites:
  1. pip install httpx (already in mcp-bridges venv)
  2. Set SUNO_API_URL to your Suno API endpoint
  3. Optionally set SUNO_API_KEY for authenticated proxy services

Security:
  - Read-heavy by design — generation is the only write op
  - No raw eval/exec of user input
  - Output capped to prevent memory issues
"""

import asyncio
import json
import os
from datetime import datetime
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("suno-bridge")

MAX_OUTPUT_BYTES = 2_000_000
POLL_INTERVAL = 5
MAX_POLL_ATTEMPTS = 60  # 5 min max wait

# Lazy init
_http_client = None


def get_client():
    global _http_client
    if _http_client is None:
        import httpx
        base_url = os.environ.get("SUNO_API_URL", "http://localhost:3000")
        headers = {"Content-Type": "application/json"}
        api_key = os.environ.get("SUNO_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        _http_client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=120.0,
        )
    return _http_client


def truncate(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    if len(text.encode("utf-8", errors="replace")) > max_bytes:
        return text[:max_bytes // 2] + "\n\n... [truncated] ..."
    return text


@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="suno_generate",
            description="Generate music from a text prompt. Returns clip IDs and audio URLs when ready.",
            inputSchema={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Description of the music to generate (genre, mood, instruments, etc.)",
                    },
                    "make_instrumental": {
                        "type": "boolean",
                        "description": "If true, generate instrumental only (no vocals). Default false.",
                        "default": False,
                    },
                    "wait_for_completion": {
                        "type": "boolean",
                        "description": "If true, poll until generation completes. Default true.",
                        "default": True,
                    },
                },
                "required": ["prompt"],
            },
        ),
        Tool(
            name="suno_custom_generate",
            description="Generate music with custom lyrics, style tags, and title. Full control over the output.",
            inputSchema={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Style/genre description (e.g. 'upbeat electronic pop with synth leads')",
                    },
                    "lyrics": {
                        "type": "string",
                        "description": "Full lyrics text. Use [Verse], [Chorus], [Bridge] tags.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Song title",
                    },
                    "make_instrumental": {
                        "type": "boolean",
                        "description": "If true, ignore lyrics and make instrumental. Default false.",
                        "default": False,
                    },
                    "wait_for_completion": {
                        "type": "boolean",
                        "description": "If true, poll until generation completes. Default true.",
                        "default": True,
                    },
                },
                "required": ["prompt"],
            },
        ),
        Tool(
            name="suno_generate_lyrics",
            description="Generate lyrics from a prompt. Returns structured lyrics with section tags.",
            inputSchema={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Description of what the lyrics should be about",
                    },
                },
                "required": ["prompt"],
            },
        ),
        Tool(
            name="suno_extend",
            description="Extend an existing Suno clip to make it longer.",
            inputSchema={
                "type": "object",
                "properties": {
                    "clip_id": {
                        "type": "string",
                        "description": "The ID of the clip to extend",
                    },
                    "prompt": {
                        "type": "string",
                        "description": "Optional style guidance for the extension",
                        "default": "",
                    },
                    "continue_at": {
                        "type": "number",
                        "description": "Timestamp in seconds to continue from. Default: end of clip.",
                    },
                    "wait_for_completion": {
                        "type": "boolean",
                        "description": "If true, poll until generation completes. Default true.",
                        "default": True,
                    },
                },
                "required": ["clip_id"],
            },
        ),
        Tool(
            name="suno_get_clip",
            description="Get metadata and audio URL for a specific Suno clip by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "clip_id": {
                        "type": "string",
                        "description": "The clip ID to look up",
                    },
                },
                "required": ["clip_id"],
            },
        ),
        Tool(
            name="suno_get_clips",
            description="Get metadata for multiple clips by their IDs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "clip_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of clip IDs to look up",
                    },
                },
                "required": ["clip_ids"],
            },
        ),
        Tool(
            name="suno_get_limit",
            description="Check remaining Suno credits/quota for the current account.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="suno_concat",
            description="Concatenate multiple Suno clips into a single continuous track.",
            inputSchema={
                "type": "object",
                "properties": {
                    "clip_id": {
                        "type": "string",
                        "description": "The base clip ID to concatenate extensions onto",
                    },
                },
                "required": ["clip_id"],
            },
        ),
        Tool(
            name="suno_generate_stems",
            description="Separate a clip into vocal and instrumental stems.",
            inputSchema={
                "type": "object",
                "properties": {
                    "clip_id": {
                        "type": "string",
                        "description": "The clip ID to separate into stems",
                    },
                },
                "required": ["clip_id"],
            },
        ),
    ]


async def poll_for_completion(clip_ids: list[str]) -> list[dict]:
    """Poll until all clips are complete or failed."""
    client = get_client()
    for attempt in range(MAX_POLL_ATTEMPTS):
        resp = await client.get("/api/get", params={"ids": ",".join(clip_ids)})
        resp.raise_for_status()
        clips = resp.json()

        if isinstance(clips, list):
            all_done = all(
                c.get("status") in ("complete", "streaming", "error")
                for c in clips
            )
            if all_done:
                return clips
        elif isinstance(clips, dict) and clips.get("status") in ("complete", "streaming", "error"):
            return [clips]

        await asyncio.sleep(POLL_INTERVAL)

    return clips if isinstance(clips, list) else [clips]


def format_clips(clips: list[dict]) -> str:
    """Format clip data for readable output."""
    lines = []
    for c in clips:
        lines.append(f"🎵 {c.get('title', 'Untitled')}")
        lines.append(f"   ID: {c.get('id', 'unknown')}")
        lines.append(f"   Status: {c.get('status', 'unknown')}")
        if c.get("audio_url"):
            lines.append(f"   Audio: {c['audio_url']}")
        if c.get("video_url"):
            lines.append(f"   Video: {c['video_url']}")
        if c.get("image_url"):
            lines.append(f"   Cover: {c['image_url']}")
        if c.get("metadata", {}).get("tags"):
            lines.append(f"   Style: {c['metadata']['tags']}")
        if c.get("metadata", {}).get("duration"):
            lines.append(f"   Duration: {c['metadata']['duration']}s")
        lines.append("")
    return "\n".join(lines)


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    client = get_client()

    try:
        if name == "suno_generate":
            payload = {
                "prompt": arguments["prompt"],
                "make_instrumental": arguments.get("make_instrumental", False),
            }
            resp = await client.post("/api/generate", json=payload)
            resp.raise_for_status()
            data = resp.json()

            clip_ids = [c["id"] for c in data] if isinstance(data, list) else [data.get("id", "")]
            clip_ids = [cid for cid in clip_ids if cid]

            if arguments.get("wait_for_completion", True) and clip_ids:
                clips = await poll_for_completion(clip_ids)
                result = format_clips(clips)
            else:
                result = f"Generation started. Clip IDs: {', '.join(clip_ids)}\nUse suno_get_clip to check status."

        elif name == "suno_custom_generate":
            payload = {
                "prompt": arguments["prompt"],
                "tags": arguments.get("prompt", ""),
                "title": arguments.get("title", ""),
                "make_instrumental": arguments.get("make_instrumental", False),
            }
            if arguments.get("lyrics"):
                payload["lyrics"] = arguments["lyrics"]

            resp = await client.post("/api/custom_generate", json=payload)
            resp.raise_for_status()
            data = resp.json()

            clip_ids = [c["id"] for c in data] if isinstance(data, list) else [data.get("id", "")]
            clip_ids = [cid for cid in clip_ids if cid]

            if arguments.get("wait_for_completion", True) and clip_ids:
                clips = await poll_for_completion(clip_ids)
                result = format_clips(clips)
            else:
                result = f"Custom generation started. Clip IDs: {', '.join(clip_ids)}\nUse suno_get_clip to check status."

        elif name == "suno_generate_lyrics":
            resp = await client.post("/api/generate_lyrics", json={"prompt": arguments["prompt"]})
            resp.raise_for_status()
            data = resp.json()
            result = data.get("text", json.dumps(data, indent=2))

        elif name == "suno_extend":
            payload = {
                "clip_id": arguments["clip_id"],
                "prompt": arguments.get("prompt", ""),
            }
            if "continue_at" in arguments:
                payload["continue_at"] = arguments["continue_at"]

            resp = await client.post("/api/extend_audio", json=payload)
            resp.raise_for_status()
            data = resp.json()

            clip_ids = [c["id"] for c in data] if isinstance(data, list) else [data.get("id", "")]
            clip_ids = [cid for cid in clip_ids if cid]

            if arguments.get("wait_for_completion", True) and clip_ids:
                clips = await poll_for_completion(clip_ids)
                result = format_clips(clips)
            else:
                result = f"Extension started. Clip IDs: {', '.join(clip_ids)}"

        elif name == "suno_get_clip":
            resp = await client.get(f"/api/clip/{arguments['clip_id']}")
            resp.raise_for_status()
            data = resp.json()
            result = format_clips([data]) if isinstance(data, dict) else json.dumps(data, indent=2)

        elif name == "suno_get_clips":
            ids = ",".join(arguments["clip_ids"])
            resp = await client.get("/api/get", params={"ids": ids})
            resp.raise_for_status()
            data = resp.json()
            clips = data if isinstance(data, list) else [data]
            result = format_clips(clips)

        elif name == "suno_get_limit":
            resp = await client.get("/api/get_limit")
            resp.raise_for_status()
            data = resp.json()
            result = json.dumps(data, indent=2)

        elif name == "suno_concat":
            resp = await client.post("/api/concat", json={"clip_id": arguments["clip_id"]})
            resp.raise_for_status()
            data = resp.json()
            result = json.dumps(data, indent=2)

        elif name == "suno_generate_stems":
            resp = await client.post("/api/generate_stems", json={"clip_id": arguments["clip_id"]})
            resp.raise_for_status()
            data = resp.json()
            result = json.dumps(data, indent=2)

        else:
            result = f"Unknown tool: {name}"

    except Exception as e:
        result = f"Error calling {name}: {type(e).__name__}: {str(e)}"

    return [TextContent(type="text", text=truncate(result))]


async def main():
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
