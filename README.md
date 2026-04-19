# MCP Bridges

Model Context Protocol (MCP) server bridges that expose CLI tools, APIs, and analysis platforms as MCP servers for AI agents. Each bridge is a standalone Python server that wraps an external tool behind the MCP stdio protocol, letting Claude Code (or any MCP-compatible agent) call it as a native tool.

All bridges include input validation, shell injection prevention, and output size limits.

## Available Bridges

### Nmap (`nmap/server.py`)
Network reconnaissance and port scanning.

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scan with configurable scan type, timing, and port range |
| `nmap_ping_sweep` | Fast host discovery on a CIDR range (no port scan) |
| `nmap_os_detect` | OS fingerprinting via TCP/IP stack analysis |
| `nmap_script` | Run NSE script categories (vuln, auth, discovery, safe, broadcast) |
| `nmap_service_versions` | Intensive service/version detection with banner grabbing |

**Prerequisite:** `brew install nmap`

---

### Nuclei (`nuclei/server.py`)
Vulnerability scanning with ProjectDiscovery's Nuclei templating engine.

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Scan a URL with severity and tag filters, JSON output |
| `nuclei_template_scan` | Run specific template IDs/paths against a target |
| `nuclei_list_templates` | List available templates by tag or severity |
| `nuclei_update` | Update nuclei templates to latest version |
| `nuclei_tech_detect` | Detect technologies (WAF, CMS, frameworks) on a target |

**Prerequisite:** `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

---

### Burp Suite (`burpsuite/server.py`)
Web security testing via Burp Suite Professional's REST API.

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `burp_scan` | Launch an active scan against one or more URLs |
| `burp_scan_status` | Check status of a running/completed scan by task ID |
| `burp_issues` | Retrieve discovered vulnerabilities, filterable by severity |
| `burp_sitemap` | Get the site map (discovered URLs and content) |
| `burp_proxy_history` | Get recent proxy history entries |
| `burp_scope` | View or modify the target scope (get/include/exclude) |
| `burp_send_to_repeater` | Send a crafted request to Burp Repeater |

**Prerequisites:**
- Burp Suite Professional running with REST API enabled on `127.0.0.1:1337`
- Set `BURP_API_KEY` env var with your generated API key

---

### Ghidra (`ghidra/server.py`)
Binary reverse engineering inspired by LaurieWired's ghidraMCP architecture. Supports two modes: HTTP (connects to Ghidra's REST plugin) and headless (runs `analyzeHeadless` directly).

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `ghidra_list_functions` | List all functions with optional name filter |
| `ghidra_decompile` | Decompile a function by address to C pseudocode |
| `ghidra_decompile_by_name` | Decompile a function by name |
| `ghidra_rename_function` | Rename a function at a given address |
| `ghidra_rename_variable` | Rename a local variable in a function |
| `ghidra_xrefs` | Get cross-references to/from an address |
| `ghidra_strings` | List strings found in the binary |
| `ghidra_imports` | List imported symbols |
| `ghidra_exports` | List exported symbols |
| `ghidra_disassemble` | Get disassembly at an address range |
| `ghidra_set_comment` | Set a comment (PRE, POST, EOL, PLATE, REPEATABLE) |
| `ghidra_binary_info` | Get binary metadata (format, arch, entry point) |
| `ghidra_search_bytes` | Search for a hex byte pattern |

**Prerequisites:**
- **HTTP mode (default):** Ghidra with HTTP plugin running on `:18489`
- **Headless mode:** Set `GHIDRA_MODE=headless` and `GHIDRA_INSTALL=/path/to/ghidra`

---

### Firebase (`firebase/server.py`)
Firebase project management via the Admin SDK -- Firestore, Auth, and Cloud Storage.

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `firestore_get` | Get a document by path |
| `firestore_query` | Query a collection with where/order/limit |
| `firestore_list_collections` | List top-level or sub-collections |
| `firestore_set` | Create or merge a document (requires `confirm=true`) |
| `firestore_delete` | Delete a document (requires `confirm=true`) |
| `firestore_count` | Count documents in a collection |
| `auth_get_user` | Look up a user by UID or email |
| `auth_list_users` | List Firebase Auth users (paginated) |
| `auth_set_custom_claims` | Set custom claims on a user (requires `confirm=true`) |
| `storage_list` | List files in a Storage bucket |
| `storage_get_url` | Generate a signed download URL |
| `storage_delete` | Delete a file (requires `confirm=true`) |

**Prerequisite:** `export GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceaccount.json`

---

### Suno (`suno/server.py`)
AI music generation via the Suno API (self-hosted or proxy).

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `suno_generate` | Generate music from a text prompt |
| `suno_custom_generate` | Generate with custom lyrics, style tags, and title |
| `suno_generate_lyrics` | Generate structured lyrics from a prompt |
| `suno_extend` | Extend an existing clip to make it longer |
| `suno_get_clip` | Get metadata and audio URL for a clip |
| `suno_get_clips` | Get metadata for multiple clips |
| `suno_get_limit` | Check remaining credits/quota |
| `suno_concat` | Concatenate clips into a single track |
| `suno_generate_stems` | Separate a clip into vocal and instrumental stems |

**Prerequisites:**
- **Self-hosted:** `docker run gcui-art/suno-api` on port 3000
- **Proxy:** Set `SUNO_API_URL` + `SUNO_API_KEY` for sunoapi.org / GoAPI / PiAPI

## Setup

### 1. Create the virtual environment

```bash
cd ~/mcp-bridges
python3 -m venv .venv
source .venv/bin/activate
pip install mcp httpx firebase-admin
```

### 2. Register all bridges with Claude Code

```bash
bash ~/mcp-bridges/register.sh
```

This registers each bridge as an MCP server using the project's `.venv` Python interpreter. You can also register individual bridges:

```bash
claude mcp add nmap-bridge -- ~/.mcp-bridges/.venv/bin/python3 ~/mcp-bridges/nmap/server.py
```

### 3. Set environment variables (per bridge)

```bash
# Burp Suite
export BURP_API_URL=http://127.0.0.1:1337
export BURP_API_KEY=your-api-key

# Ghidra
export GHIDRA_URL=http://localhost:18489   # HTTP mode
export GHIDRA_MODE=headless                # or headless mode
export GHIDRA_INSTALL=/opt/ghidra          # path to Ghidra install

# Firebase
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceaccount.json
export FIREBASE_PROJECT_ID=your-project    # alternative to credentials file

# Suno
export SUNO_API_URL=http://localhost:3000
export SUNO_API_KEY=your-key               # only for proxy services
```

## Requirements

- Python 3.11+
- `mcp` (Model Context Protocol SDK)
- `httpx` (async HTTP client, used by Burp Suite, Ghidra, and Suno bridges)
- `firebase-admin` (only for the Firebase bridge)
- Each bridge's underlying tool installed separately (nmap, nuclei, Burp Pro, Ghidra, Suno API)

## Architecture

Each bridge follows the same pattern:

```
bridge/server.py
    ├── Input validation and sanitization
    ├── Tool definitions via @app.list_tools()
    ├── Tool dispatch via @app.call_tool()
    └── Subprocess execution (CLI tools) or HTTP requests (API tools)
```

All bridges communicate over stdio using the MCP protocol. Claude Code spawns each bridge as a child process and sends/receives JSON-RPC messages.

## Security

- All inputs are validated and sanitized before use
- Shell metacharacters are blocked in subprocess-based bridges (nmap, nuclei)
- Output is capped (500KB-2MB per bridge) to prevent memory exhaustion
- Destructive operations in Firebase require an explicit `confirm=true` parameter
- No `eval()`, `exec()`, or shell=True anywhere in the codebase

## License

All rights reserved.
