#!/usr/bin/env python3
"""
MCP Bridge: Nmap — Network reconnaissance via MCP protocol.
Hardened: input validation, no shell injection, output size limits.
"""

import asyncio
import ipaddress
import re
import shutil
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("nmap-bridge")

# --- Security ---
MAX_OUTPUT_BYTES = 500_000  # 500KB cap
ALLOWED_SCAN_TYPES = {"-sS", "-sT", "-sU", "-sV", "-sC", "-sn", "-sA", "-sW", "-sN"}
ALLOWED_TIMING = {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}
BLOCKED_ARGS = {"--script=", "-iL", "-oG", "-oN", "-oX", "-oA", "--resume", "--stylesheet"}


def validate_target(target: str) -> str:
    """Validate target is an IP, CIDR, or hostname — no shell metacharacters."""
    target = target.strip()
    if not target:
        raise ValueError("Empty target")
    # Block shell metacharacters
    if re.search(r'[;&|`$(){}\'\"\\<>\n\r]', target):
        raise ValueError(f"Illegal characters in target: {target}")
    # Try as IP/CIDR
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    # Hostname: alphanumeric, dots, hyphens, slashes for CIDR
    if re.match(r'^[a-zA-Z0-9.\-/]+$', target) and len(target) <= 253:
        return target
    raise ValueError(f"Invalid target format: {target}")


def validate_ports(ports: str) -> str:
    """Validate port specification."""
    ports = ports.strip()
    if not ports:
        return ""
    if re.match(r'^[\d,\-]+$', ports) and len(ports) <= 200:
        return ports
    if ports in ("T:", "U:", "-"):
        return ports
    raise ValueError(f"Invalid port spec: {ports}")


def validate_args(args: list[str]) -> list[str]:
    """Filter nmap arguments against allowlist, block dangerous flags."""
    clean = []
    for arg in args:
        arg = arg.strip()
        if not arg:
            continue
        for blocked in BLOCKED_ARGS:
            if arg.startswith(blocked):
                raise ValueError(f"Blocked argument: {arg}")
        if re.search(r'[;&|`$(){}\'\"\\<>\n\r]', arg):
            raise ValueError(f"Illegal characters in argument: {arg}")
        clean.append(arg)
    return clean


async def run_nmap(args: list[str], timeout: int = 300) -> str:
    """Execute nmap with validated arguments."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return "ERROR: nmap not found in PATH. Install with: brew install nmap"

    cmd = [nmap_path] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")
        if stderr:
            output += "\n--- STDERR ---\n" + stderr.decode("utf-8", errors="replace")
        if len(output) > MAX_OUTPUT_BYTES:
            output = output[:MAX_OUTPUT_BYTES] + f"\n\n[TRUNCATED at {MAX_OUTPUT_BYTES} bytes]"
        return output
    except asyncio.TimeoutError:
        proc.kill()
        return f"ERROR: Scan timed out after {timeout}s"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="nmap_scan",
            description="Run a port scan against a target. Returns open ports, services, and versions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address, CIDR range, or hostname"},
                    "ports": {"type": "string", "description": "Port spec (e.g. '80,443', '1-1000', '22-25,80,443'). Empty = nmap default (top 1000)", "default": ""},
                    "scan_type": {"type": "string", "enum": list(ALLOWED_SCAN_TYPES), "description": "Scan type flag", "default": "-sV"},
                    "timing": {"type": "string", "enum": list(ALLOWED_TIMING), "description": "Timing template", "default": "-T3"},
                    "extra_args": {"type": "array", "items": {"type": "string"}, "description": "Additional nmap flags (validated)", "default": []},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="nmap_ping_sweep",
            description="Discover live hosts on a network (no port scan). Fast host discovery.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "CIDR range (e.g. '192.168.1.0/24')"},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="nmap_os_detect",
            description="Attempt OS detection on a target. Requires sufficient open/closed ports.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname"},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="nmap_script",
            description="Run an NSE script category against a target. Categories: default, vuln, auth, discovery, safe.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname"},
                    "category": {
                        "type": "string",
                        "enum": ["default", "vuln", "auth", "discovery", "safe", "broadcast"],
                        "description": "NSE script category",
                    },
                    "ports": {"type": "string", "description": "Port spec", "default": ""},
                },
                "required": ["target", "category"],
            },
        ),
        Tool(
            name="nmap_service_versions",
            description="Intensive service/version detection with banner grabbing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname"},
                    "ports": {"type": "string", "description": "Port spec", "default": ""},
                },
                "required": ["target"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "nmap_scan":
            target = validate_target(arguments["target"])
            args = [arguments.get("scan_type", "-sV"), arguments.get("timing", "-T3")]
            ports = validate_ports(arguments.get("ports", ""))
            if ports:
                args += ["-p", ports]
            extra = validate_args(arguments.get("extra_args", []))
            args += extra + [target]
            result = await run_nmap(args)

        elif name == "nmap_ping_sweep":
            target = validate_target(arguments["target"])
            result = await run_nmap(["-sn", "-T3", target])

        elif name == "nmap_os_detect":
            target = validate_target(arguments["target"])
            result = await run_nmap(["-O", "--osscan-guess", "-T3", target])

        elif name == "nmap_script":
            target = validate_target(arguments["target"])
            category = arguments["category"]
            allowed_cats = {"default", "vuln", "auth", "discovery", "safe", "broadcast"}
            if category not in allowed_cats:
                return [TextContent(type="text", text=f"ERROR: Invalid category. Use: {allowed_cats}")]
            args = ["-sV", f"--script={category}", "-T3"]
            ports = validate_ports(arguments.get("ports", ""))
            if ports:
                args += ["-p", ports]
            args.append(target)
            result = await run_nmap(args, timeout=600)

        elif name == "nmap_service_versions":
            target = validate_target(arguments["target"])
            args = ["-sV", "--version-intensity", "9", "-T3"]
            ports = validate_ports(arguments.get("ports", ""))
            if ports:
                args += ["-p", ports]
            args.append(target)
            result = await run_nmap(args)

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
