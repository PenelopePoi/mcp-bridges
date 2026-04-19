#!/bin/bash
# Register all MCP bridges with Claude Code
# Run: bash ~/mcp-bridges/register.sh

VENV="/Users/TroubleshootGuest/mcp-bridges/.venv/bin/python3"
DIR="/Users/TroubleshootGuest/mcp-bridges"

echo "=== Registering MCP Bridges ==="

# Nmap — network recon
claude mcp add nmap-bridge -- "$VENV" "$DIR/nmap/server.py"
echo "✓ nmap-bridge"

# Nuclei — vuln scanning
claude mcp add nuclei-bridge -- "$VENV" "$DIR/nuclei/server.py"
echo "✓ nuclei-bridge"

# Burp Suite — web security (needs BURP_API_URL and BURP_API_KEY env vars)
claude mcp add burpsuite-bridge -e BURP_API_URL=http://127.0.0.1:1337 -- "$VENV" "$DIR/burpsuite/server.py"
echo "✓ burpsuite-bridge"

# Ghidra — reverse engineering (needs GHIDRA_URL or GHIDRA_INSTALL env vars)
claude mcp add ghidra-bridge -e GHIDRA_URL=http://localhost:18489 -- "$VENV" "$DIR/ghidra/server.py"
echo "✓ ghidra-bridge"

# Firebase — Firestore/Auth/Storage (needs GOOGLE_APPLICATION_CREDENTIALS env var)
claude mcp add firebase-bridge -- "$VENV" "$DIR/firebase/server.py"
echo "✓ firebase-bridge"

# Suno — AI Music Generation (needs SUNO_API_URL, optionally SUNO_API_KEY)
claude mcp add suno-bridge -e SUNO_API_URL=http://localhost:3000 -- "$VENV" "$DIR/suno/server.py"
echo "✓ suno-bridge"

echo ""
echo "=== All 6 bridges registered ==="
echo ""
echo "Prerequisites per bridge:"
echo "  nmap:      brew install nmap"
echo "  nuclei:    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
echo "  burpsuite: Burp Pro running with REST API on :1337"
echo "  ghidra:    Ghidra with HTTP plugin on :18489 (or set GHIDRA_INSTALL for headless)"
echo "  firebase:  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceaccount.json"
echo "  suno:      Self-hosted: docker run gcui-art/suno-api on :3000"
echo "             OR proxy: set SUNO_API_URL + SUNO_API_KEY for sunoapi.org/GoAPI/PiAPI"
