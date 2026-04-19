#!/usr/bin/env python3
"""
MCP Bridge: Burp Suite — Web security testing via Burp REST API.
Connects to Burp Suite Professional's REST API (must be running).
Hardened: input validation, auth token support, output limits.

Prerequisites:
  1. Burp Suite Pro running with REST API enabled
  2. User Options → Misc → REST API: enabled on 127.0.0.1:1337
  3. Generate an API key in Burp and set BURP_API_KEY env var
"""

import asyncio
import json
import os
import re
from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx

app = Server("burpsuite-bridge")

BURP_URL = os.environ.get("BURP_API_URL", "http://127.0.0.1:1337")
BURP_API_KEY = os.environ.get("BURP_API_KEY", "")
MAX_OUTPUT_BYTES = 1_000_000
BLOCKED_CHARS = set(';&|`$(){}\'\"\\<>\n\r')


def sanitize(value: str, max_len: int = 2000) -> str:
    value = value.strip()[:max_len]
    if any(c in BLOCKED_CHARS for c in value):
        raise ValueError(f"Illegal characters in input")
    return value


def validate_url(url: str) -> str:
    url = sanitize(url, 2000)
    if not re.match(r'^https?://[a-zA-Z0-9.\-:/@%?&=_~#+\[\]]+$', url):
        raise ValueError(f"Invalid URL: {url}")
    return url


def get_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if BURP_API_KEY:
        headers["Authorization"] = f"Bearer {BURP_API_KEY}"
    return headers


async def burp_request(method: str, path: str, data: dict | None = None, timeout: int = 30) -> str:
    """Make authenticated request to Burp REST API."""
    try:
        async with httpx.AsyncClient(verify=False) as client:
            url = f"{BURP_URL}{path}"
            if method == "GET":
                r = await client.get(url, headers=get_headers(), timeout=timeout)
            elif method == "POST":
                r = await client.post(url, headers=get_headers(), json=data or {}, timeout=timeout)
            elif method == "DELETE":
                r = await client.delete(url, headers=get_headers(), timeout=timeout)
            else:
                return f"ERROR: Unsupported method: {method}"

            output = r.text
            if len(output) > MAX_OUTPUT_BYTES:
                output = output[:MAX_OUTPUT_BYTES] + f"\n[TRUNCATED at {MAX_OUTPUT_BYTES} bytes]"
            return output
    except httpx.ConnectError:
        return f"ERROR: Cannot connect to Burp at {BURP_URL}. Is Burp running with REST API enabled?"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="burp_scan",
            description="Launch an active scan against a URL. Returns scan ID for status tracking.",
            inputSchema={
                "type": "object",
                "properties": {
                    "urls": {"type": "array", "items": {"type": "string"}, "description": "URLs to scan"},
                    "scope_only": {"type": "boolean", "description": "Only scan in-scope URLs", "default": True},
                },
                "required": ["urls"],
            },
        ),
        Tool(
            name="burp_scan_status",
            description="Check status of a running or completed scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Scan task ID from burp_scan"},
                },
                "required": ["task_id"],
            },
        ),
        Tool(
            name="burp_issues",
            description="Get all discovered issues/vulnerabilities from the current scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url_filter": {"type": "string", "description": "Filter issues by URL prefix", "default": ""},
                    "severity": {"type": "string", "enum": ["high", "medium", "low", "info", ""], "description": "Filter by severity", "default": ""},
                },
            },
        ),
        Tool(
            name="burp_sitemap",
            description="Get the site map (discovered URLs and content) from Burp.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url_prefix": {"type": "string", "description": "Filter by URL prefix"},
                },
                "required": ["url_prefix"],
            },
        ),
        Tool(
            name="burp_proxy_history",
            description="Get recent proxy history entries (requests/responses that passed through Burp proxy).",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max entries to return", "default": 50},
                },
            },
        ),
        Tool(
            name="burp_scope",
            description="View or modify the target scope.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["get", "include", "exclude"], "description": "Action to perform"},
                    "url": {"type": "string", "description": "URL to include/exclude (not needed for 'get')", "default": ""},
                },
                "required": ["action"],
            },
        ),
        Tool(
            name="burp_send_to_repeater",
            description="Send a request to Burp Repeater for manual testing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to send"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"], "default": "GET"},
                    "headers": {"type": "object", "description": "Custom headers", "default": {}},
                    "body": {"type": "string", "description": "Request body", "default": ""},
                },
                "required": ["url"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "burp_scan":
            urls = [validate_url(u) for u in arguments["urls"]]
            data = {
                "urls": urls,
                "scope": {"type": "SimpleScope", "include": [{"rule": u} for u in urls]},
            }
            result = await burp_request("POST", "/v0.1/scan", data)

        elif name == "burp_scan_status":
            task_id = sanitize(arguments["task_id"], 100)
            if not re.match(r'^[\w\-]+$', task_id):
                return [TextContent(type="text", text="ERROR: Invalid task ID format")]
            result = await burp_request("GET", f"/v0.1/scan/{task_id}")

        elif name == "burp_issues":
            url_filter = arguments.get("url_filter", "")
            if url_filter:
                url_filter = validate_url(url_filter)
            result = await burp_request("GET", "/v0.1/knowledge_base/issue_definitions")
            # Try to filter and format
            try:
                issues = json.loads(result)
                if url_filter:
                    issues = [i for i in issues if url_filter in i.get("url", "")]
                severity = arguments.get("severity", "")
                if severity:
                    issues = [i for i in issues if i.get("severity", "").lower() == severity]
                result = json.dumps(issues, indent=2)
            except (json.JSONDecodeError, TypeError):
                pass  # Return raw result

        elif name == "burp_sitemap":
            prefix = validate_url(arguments["url_prefix"])
            result = await burp_request("GET", f"/v0.1/sitemap?urlPrefix={prefix}")

        elif name == "burp_proxy_history":
            limit = min(arguments.get("limit", 50), 500)
            result = await burp_request("GET", f"/v0.1/proxy/history?limit={limit}")

        elif name == "burp_scope":
            action = arguments["action"]
            if action == "get":
                result = await burp_request("GET", "/v0.1/target/scope")
            elif action in ("include", "exclude"):
                url = validate_url(arguments.get("url", ""))
                if not url:
                    return [TextContent(type="text", text="ERROR: URL required for include/exclude")]
                result = await burp_request("PUT", f"/v0.1/target/scope/{action}", {"url": url})
            else:
                result = "ERROR: Invalid action"

        elif name == "burp_send_to_repeater":
            url = validate_url(arguments["url"])
            data = {
                "request": {
                    "url": url,
                    "method": arguments.get("method", "GET"),
                    "headers": arguments.get("headers", {}),
                    "body": arguments.get("body", ""),
                }
            }
            result = await burp_request("POST", "/v0.1/repeater", data)

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
