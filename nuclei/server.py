#!/usr/bin/env python3
"""
MCP Bridge: Nuclei — Vulnerability scanning via MCP protocol.
Hardened: input validation, no shell injection, JSON output parsing.
"""

import asyncio
import json
import re
import shutil
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("nuclei-bridge")

MAX_OUTPUT_BYTES = 1_000_000  # 1MB cap
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_TYPES = {"http", "dns", "tcp", "ssl", "file", "headless", "network"}
BLOCKED_PATTERNS = [";", "&", "|", "`", "$", "(", ")", "{", "}", "'", '"', "\\", "<", ">", "\n", "\r"]


def sanitize(value: str, max_len: int = 500) -> str:
    """Strip dangerous characters."""
    value = value.strip()[:max_len]
    for ch in BLOCKED_PATTERNS:
        if ch in value:
            raise ValueError(f"Illegal character '{ch}' in input")
    return value


def validate_url(url: str) -> str:
    """Validate URL format."""
    url = sanitize(url, 2000)
    if not re.match(r'^https?://[a-zA-Z0-9.\-:/@%?&=_~#+\[\]]+$', url):
        raise ValueError(f"Invalid URL format: {url}")
    return url


def validate_target(target: str) -> str:
    """Validate target — URL or hostname."""
    target = sanitize(target, 2000)
    # Allow URLs
    if target.startswith(("http://", "https://")):
        return validate_url(target)
    # Allow hostnames/IPs
    if re.match(r'^[a-zA-Z0-9.\-:/]+$', target):
        return target
    raise ValueError(f"Invalid target: {target}")


async def run_nuclei(args: list[str], timeout: int = 600) -> str:
    """Execute nuclei with validated arguments."""
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return "ERROR: nuclei not found in PATH. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    cmd = [nuclei_path] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")
        if len(output) > MAX_OUTPUT_BYTES:
            output = output[:MAX_OUTPUT_BYTES] + f"\n\n[TRUNCATED at {MAX_OUTPUT_BYTES} bytes]"
        return output if output.strip() else "(No findings)"
    except asyncio.TimeoutError:
        proc.kill()
        return f"ERROR: Scan timed out after {timeout}s"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="nuclei_scan",
            description="Run nuclei vulnerability scan against a target URL. Returns findings in JSON.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL (e.g. https://example.com)"},
                    "severity": {
                        "type": "array",
                        "items": {"type": "string", "enum": list(ALLOWED_SEVERITIES)},
                        "description": "Filter by severity levels",
                        "default": ["medium", "high", "critical"],
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Template tags to include (e.g. ['cve', 'xss', 'sqli'])",
                        "default": [],
                    },
                    "rate_limit": {"type": "integer", "description": "Max requests per second", "default": 50},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="nuclei_template_scan",
            description="Run specific nuclei templates against a target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                    "templates": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Template IDs or paths (e.g. ['cves/2024/', 'vulnerabilities/xss/'])",
                    },
                },
                "required": ["target", "templates"],
            },
        ),
        Tool(
            name="nuclei_list_templates",
            description="List available nuclei templates filtered by tags or severity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter by tags", "default": []},
                    "severity": {"type": "string", "enum": list(ALLOWED_SEVERITIES), "description": "Filter by severity"},
                },
            },
        ),
        Tool(
            name="nuclei_update",
            description="Update nuclei templates to latest version.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="nuclei_tech_detect",
            description="Detect technologies running on a target (WAF, CMS, frameworks, etc.).",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                },
                "required": ["target"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "nuclei_scan":
            target = validate_target(arguments["target"])
            severities = arguments.get("severity", ["medium", "high", "critical"])
            for s in severities:
                if s not in ALLOWED_SEVERITIES:
                    return [TextContent(type="text", text=f"ERROR: Invalid severity: {s}")]

            args = ["-u", target, "-jsonl", "-severity", ",".join(severities)]
            tags = arguments.get("tags", [])
            if tags:
                for t in tags:
                    sanitize(t, 50)
                args += ["-tags", ",".join(tags)]
            rate = min(arguments.get("rate_limit", 50), 200)
            args += ["-rl", str(rate), "-silent"]
            result = await run_nuclei(args)

        elif name == "nuclei_template_scan":
            target = validate_target(arguments["target"])
            templates = arguments.get("templates", [])
            args = ["-u", target, "-jsonl", "-silent"]
            for t in templates:
                t = sanitize(t, 200)
                args += ["-t", t]
            result = await run_nuclei(args)

        elif name == "nuclei_list_templates":
            args = ["-tl"]
            tags = arguments.get("tags", [])
            if tags:
                for t in tags:
                    sanitize(t, 50)
                args += ["-tags", ",".join(tags)]
            severity = arguments.get("severity", "")
            if severity:
                if severity not in ALLOWED_SEVERITIES:
                    return [TextContent(type="text", text=f"ERROR: Invalid severity: {severity}")]
                args += ["-severity", severity]
            result = await run_nuclei(args, timeout=30)

        elif name == "nuclei_update":
            result = await run_nuclei(["-ut", "-ud"], timeout=120)

        elif name == "nuclei_tech_detect":
            target = validate_target(arguments["target"])
            result = await run_nuclei(["-u", target, "-tags", "tech", "-jsonl", "-silent"])

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
