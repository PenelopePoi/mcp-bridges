#!/usr/bin/env python3
"""
MCP Bridge: Ghidra — Reverse engineering via MCP protocol.
Inspired by LaurieWired's ghidraMCP architecture.

Two modes:
  1. HTTP mode: connects to Ghidra plugin REST server (requires GhidraHttpPlugin)
  2. Headless mode: runs Ghidra headless analyzer directly (no GUI needed)

Set GHIDRA_MODE=http or GHIDRA_MODE=headless (default: http)
Set GHIDRA_URL for HTTP mode (default: http://localhost:18489)
Set GHIDRA_INSTALL for headless mode (default: /opt/ghidra)
"""

import asyncio
import json
import os
import re
import shutil
from pathlib import Path
from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx

app = Server("ghidra-bridge")

GHIDRA_MODE = os.environ.get("GHIDRA_MODE", "http")
GHIDRA_URL = os.environ.get("GHIDRA_URL", "http://localhost:18489")
GHIDRA_INSTALL = os.environ.get("GHIDRA_INSTALL", "/opt/ghidra")
MAX_OUTPUT_BYTES = 2_000_000  # 2MB — decompilation output can be large
BLOCKED_CHARS = set(';&|`$\n\r')


def sanitize(value: str, max_len: int = 500) -> str:
    value = value.strip()[:max_len]
    if any(c in BLOCKED_CHARS for c in value):
        raise ValueError(f"Illegal characters in input")
    return value


def validate_address(addr: str) -> str:
    """Validate hex address format."""
    addr = sanitize(addr, 20)
    if not re.match(r'^(0x)?[0-9a-fA-F]+$', addr):
        raise ValueError(f"Invalid address format: {addr}")
    return addr


def validate_name(name: str) -> str:
    """Validate function/variable name — alphanumeric + underscore."""
    name = sanitize(name, 200)
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        raise ValueError(f"Invalid name: {name}")
    return name


def validate_filepath(path: str) -> str:
    """Validate binary file path exists and is a file."""
    path = sanitize(path, 1000)
    p = Path(path).resolve()
    if not p.is_file():
        raise ValueError(f"File not found: {path}")
    return str(p)


async def ghidra_http(method: str, endpoint: str, data: dict | None = None) -> str:
    """Request to Ghidra HTTP plugin."""
    try:
        async with httpx.AsyncClient() as client:
            url = f"{GHIDRA_URL}{endpoint}"
            if method == "GET":
                r = await client.get(url, timeout=30)
            elif method == "POST":
                r = await client.post(url, json=data or {}, timeout=60)
            else:
                return f"ERROR: Unsupported method"
            output = r.text
            if len(output) > MAX_OUTPUT_BYTES:
                output = output[:MAX_OUTPUT_BYTES] + "\n[TRUNCATED]"
            return output
    except httpx.ConnectError:
        return f"ERROR: Cannot connect to Ghidra at {GHIDRA_URL}. Is the HTTP plugin running?"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


async def ghidra_headless(binary: str, script_name: str, script_args: list[str] | None = None, timeout: int = 120) -> str:
    """Run Ghidra in headless mode with a script."""
    analyze_path = shutil.which("analyzeHeadless")
    if not analyze_path:
        headless = Path(GHIDRA_INSTALL) / "support" / "analyzeHeadless"
        if headless.exists():
            analyze_path = str(headless)
        else:
            return f"ERROR: analyzeHeadless not found. Set GHIDRA_INSTALL or add to PATH."

    project_dir = "/tmp/ghidra_mcp_projects"
    os.makedirs(project_dir, exist_ok=True)
    project_name = f"mcp_{Path(binary).stem}"

    cmd = [
        analyze_path, project_dir, project_name,
        "-import", binary,
        "-overwrite",
        "-postScript", script_name,
    ]
    if script_args:
        cmd += script_args

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")
        if len(output) > MAX_OUTPUT_BYTES:
            output = output[:MAX_OUTPUT_BYTES] + "\n[TRUNCATED]"
        return output
    except asyncio.TimeoutError:
        proc.kill()
        return f"ERROR: Analysis timed out after {timeout}s"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="ghidra_list_functions",
            description="List all functions in the loaded binary. Returns name, address, size.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Filter functions by name substring", "default": ""},
                },
            },
        ),
        Tool(
            name="ghidra_decompile",
            description="Decompile a function at the given address. Returns C-like pseudocode.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Function address (hex, e.g. '0x401000')"},
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="ghidra_decompile_by_name",
            description="Decompile a function by its name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Function name (e.g. 'main', 'FUN_00401000')"},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="ghidra_rename_function",
            description="Rename a function at the given address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Function address (hex)"},
                    "new_name": {"type": "string", "description": "New function name"},
                },
                "required": ["address", "new_name"],
            },
        ),
        Tool(
            name="ghidra_rename_variable",
            description="Rename a local variable in a function.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_address": {"type": "string", "description": "Function address"},
                    "old_name": {"type": "string", "description": "Current variable name"},
                    "new_name": {"type": "string", "description": "New variable name"},
                },
                "required": ["function_address", "old_name", "new_name"],
            },
        ),
        Tool(
            name="ghidra_xrefs",
            description="Get cross-references to/from an address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address (hex)"},
                    "direction": {"type": "string", "enum": ["to", "from", "both"], "default": "both"},
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="ghidra_strings",
            description="List all strings found in the binary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_length": {"type": "integer", "description": "Minimum string length", "default": 4},
                    "filter": {"type": "string", "description": "Filter by substring", "default": ""},
                },
            },
        ),
        Tool(
            name="ghidra_imports",
            description="List all imported functions/symbols.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="ghidra_exports",
            description="List all exported functions/symbols.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="ghidra_disassemble",
            description="Get disassembly (assembly code) at an address range.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Start address (hex)"},
                    "length": {"type": "integer", "description": "Number of instructions", "default": 50},
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="ghidra_set_comment",
            description="Set a comment at an address (PRE, POST, EOL, PLATE, REPEATABLE).",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address (hex)"},
                    "comment": {"type": "string", "description": "Comment text"},
                    "comment_type": {"type": "string", "enum": ["PRE", "POST", "EOL", "PLATE", "REPEATABLE"], "default": "EOL"},
                },
                "required": ["address", "comment"],
            },
        ),
        Tool(
            name="ghidra_binary_info",
            description="Get metadata about the loaded binary (format, arch, entry point, etc.).",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="ghidra_search_bytes",
            description="Search for a byte pattern in the binary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Hex byte pattern (e.g. '48 89 e5' or '488945??')"},
                },
                "required": ["pattern"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "ghidra_list_functions":
            filt = sanitize(arguments.get("filter", ""), 100)
            if filt:
                result = await ghidra_http("GET", f"/api/functions?filter={filt}")
            else:
                result = await ghidra_http("GET", "/api/functions")

        elif name == "ghidra_decompile":
            addr = validate_address(arguments["address"])
            result = await ghidra_http("GET", f"/api/decompile/{addr}")

        elif name == "ghidra_decompile_by_name":
            fname = validate_name(arguments["name"])
            result = await ghidra_http("GET", f"/api/decompile/name/{fname}")

        elif name == "ghidra_rename_function":
            addr = validate_address(arguments["address"])
            new_name = validate_name(arguments["new_name"])
            result = await ghidra_http("POST", f"/api/rename/{addr}", {"name": new_name})

        elif name == "ghidra_rename_variable":
            func_addr = validate_address(arguments["function_address"])
            old = validate_name(arguments["old_name"])
            new = validate_name(arguments["new_name"])
            result = await ghidra_http("POST", f"/api/rename_variable/{func_addr}", {
                "old_name": old, "new_name": new
            })

        elif name == "ghidra_xrefs":
            addr = validate_address(arguments["address"])
            direction = arguments.get("direction", "both")
            result = await ghidra_http("GET", f"/api/xrefs/{addr}?direction={direction}")

        elif name == "ghidra_strings":
            min_len = max(1, min(arguments.get("min_length", 4), 100))
            filt = sanitize(arguments.get("filter", ""), 100)
            result = await ghidra_http("GET", f"/api/strings?min_length={min_len}&filter={filt}")

        elif name == "ghidra_imports":
            result = await ghidra_http("GET", "/api/imports")

        elif name == "ghidra_exports":
            result = await ghidra_http("GET", "/api/exports")

        elif name == "ghidra_disassemble":
            addr = validate_address(arguments["address"])
            length = max(1, min(arguments.get("length", 50), 500))
            result = await ghidra_http("GET", f"/api/disassemble/{addr}?length={length}")

        elif name == "ghidra_set_comment":
            addr = validate_address(arguments["address"])
            comment = sanitize(arguments["comment"], 1000)
            ctype = arguments.get("comment_type", "EOL")
            if ctype not in {"PRE", "POST", "EOL", "PLATE", "REPEATABLE"}:
                return [TextContent(type="text", text="ERROR: Invalid comment type")]
            result = await ghidra_http("POST", f"/api/comment/{addr}", {
                "comment": comment, "type": ctype
            })

        elif name == "ghidra_binary_info":
            result = await ghidra_http("GET", "/api/info")

        elif name == "ghidra_search_bytes":
            pattern = sanitize(arguments["pattern"], 200)
            if not re.match(r'^[0-9a-fA-F? ]+$', pattern):
                return [TextContent(type="text", text="ERROR: Pattern must be hex bytes (e.g. '48 89 e5 ??')")]
            result = await ghidra_http("GET", f"/api/search/bytes?pattern={pattern}")

        else:
            result = f"ERROR: Unknown tool: {name}"

        return [TextContent(type="text", text=result)]

    except ValueError as e:
        return [TextContent(type="text", text=f"VALIDATION ERROR: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"ERROR: {type(e).__name__}: {e}")]


if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(main())
