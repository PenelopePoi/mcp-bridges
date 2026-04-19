#!/usr/bin/env python3
"""
MCP Bridge: Firebase — Firestore, Auth, and Storage via MCP protocol.
Uses Firebase Admin SDK for secure server-side access.

Prerequisites:
  1. pip install firebase-admin
  2. Set GOOGLE_APPLICATION_CREDENTIALS to your service account JSON path
  3. Or set FIREBASE_PROJECT_ID and use default credentials (gcloud auth)

Security:
  - Read-heavy by design — destructive ops require explicit confirmation flags
  - Query results are capped to prevent memory issues
  - No raw eval/exec of user input
  - Collection/document paths validated against injection
"""

import asyncio
import json
import os
import re
from datetime import datetime
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("firebase-bridge")

MAX_RESULTS = 500
MAX_OUTPUT_BYTES = 1_000_000
BLOCKED_CHARS = set(';&|`$(){}\'\"\\<>\n\r')

# Lazy init — only import firebase when first tool is called
_firebase_initialized = False


def init_firebase():
    global _firebase_initialized
    if _firebase_initialized:
        return
    try:
        import firebase_admin
        from firebase_admin import credentials

        cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        project_id = os.environ.get("FIREBASE_PROJECT_ID")

        if cred_path and os.path.isfile(cred_path):
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
        elif project_id:
            firebase_admin.initialize_app(options={"projectId": project_id})
        else:
            firebase_admin.initialize_app()

        _firebase_initialized = True
    except Exception as e:
        raise RuntimeError(f"Firebase init failed: {e}. Set GOOGLE_APPLICATION_CREDENTIALS or FIREBASE_PROJECT_ID.")


def sanitize(value: str, max_len: int = 500) -> str:
    value = value.strip()[:max_len]
    if any(c in BLOCKED_CHARS for c in value):
        raise ValueError(f"Illegal characters in input")
    return value


def validate_path(path: str) -> str:
    """Validate Firestore collection/document path — no injection."""
    path = sanitize(path, 500)
    # Only allow alphanumeric, underscores, hyphens, dots, slashes
    if not re.match(r'^[a-zA-Z0-9_\-./]+$', path):
        raise ValueError(f"Invalid path: {path}")
    # No double slashes or traversal
    if '//' in path or '..' in path:
        raise ValueError(f"Path traversal not allowed: {path}")
    return path


def serialize_doc(doc) -> dict:
    """Serialize Firestore document to JSON-safe dict."""
    data = doc.to_dict() or {}
    # Convert datetime objects
    for k, v in data.items():
        if isinstance(v, datetime):
            data[k] = v.isoformat()
    return {"id": doc.id, "path": doc.reference.path, "data": data}


def truncate(text: str) -> str:
    if len(text) > MAX_OUTPUT_BYTES:
        return text[:MAX_OUTPUT_BYTES] + "\n[TRUNCATED]"
    return text


@app.list_tools()
async def list_tools():
    return [
        # --- Firestore ---
        Tool(
            name="firestore_get",
            description="Get a single document by path (e.g. 'users/abc123').",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Document path (collection/doc_id)"},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="firestore_query",
            description="Query a Firestore collection with optional filters, ordering, and limits.",
            inputSchema={
                "type": "object",
                "properties": {
                    "collection": {"type": "string", "description": "Collection path"},
                    "where": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "field": {"type": "string"},
                                "op": {"type": "string", "enum": ["==", "!=", "<", "<=", ">", ">=", "in", "not-in", "array-contains", "array-contains-any"]},
                                "value": {},
                            },
                            "required": ["field", "op", "value"],
                        },
                        "description": "Filter conditions",
                        "default": [],
                    },
                    "order_by": {"type": "string", "description": "Field to order by", "default": ""},
                    "order_dir": {"type": "string", "enum": ["asc", "desc"], "default": "asc"},
                    "limit": {"type": "integer", "description": "Max results", "default": 50},
                },
                "required": ["collection"],
            },
        ),
        Tool(
            name="firestore_list_collections",
            description="List top-level collections, or subcollections of a document.",
            inputSchema={
                "type": "object",
                "properties": {
                    "parent_path": {"type": "string", "description": "Document path for subcollections (empty = top-level)", "default": ""},
                },
            },
        ),
        Tool(
            name="firestore_set",
            description="Create or overwrite a document. Requires confirm=true for safety.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Document path"},
                    "data": {"type": "object", "description": "Document data"},
                    "merge": {"type": "boolean", "description": "Merge with existing (true) or overwrite (false)", "default": True},
                    "confirm": {"type": "boolean", "description": "Must be true to execute write", "default": False},
                },
                "required": ["path", "data", "confirm"],
            },
        ),
        Tool(
            name="firestore_delete",
            description="Delete a document. Requires confirm=true for safety.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Document path"},
                    "confirm": {"type": "boolean", "description": "Must be true to execute delete", "default": False},
                },
                "required": ["path", "confirm"],
            },
        ),
        Tool(
            name="firestore_count",
            description="Count documents in a collection (with optional filters).",
            inputSchema={
                "type": "object",
                "properties": {
                    "collection": {"type": "string", "description": "Collection path"},
                    "where": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "field": {"type": "string"},
                                "op": {"type": "string"},
                                "value": {},
                            },
                        },
                        "default": [],
                    },
                },
                "required": ["collection"],
            },
        ),
        # --- Auth ---
        Tool(
            name="auth_get_user",
            description="Get Firebase Auth user by UID or email.",
            inputSchema={
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "User UID", "default": ""},
                    "email": {"type": "string", "description": "User email", "default": ""},
                },
            },
        ),
        Tool(
            name="auth_list_users",
            description="List Firebase Auth users (paginated).",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max users to return", "default": 50},
                    "page_token": {"type": "string", "description": "Pagination token", "default": ""},
                },
            },
        ),
        Tool(
            name="auth_set_custom_claims",
            description="Set custom claims on a user (e.g. admin role). Requires confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "User UID"},
                    "claims": {"type": "object", "description": "Custom claims dict"},
                    "confirm": {"type": "boolean", "default": False},
                },
                "required": ["uid", "claims", "confirm"],
            },
        ),
        # --- Storage ---
        Tool(
            name="storage_list",
            description="List files in a Firebase Storage bucket path.",
            inputSchema={
                "type": "object",
                "properties": {
                    "prefix": {"type": "string", "description": "Path prefix (e.g. 'uploads/images/')", "default": ""},
                    "limit": {"type": "integer", "description": "Max files", "default": 100},
                },
            },
        ),
        Tool(
            name="storage_get_url",
            description="Get a signed download URL for a file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path in bucket"},
                    "expiration_hours": {"type": "integer", "description": "URL expiration in hours", "default": 1},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="storage_delete",
            description="Delete a file from Storage. Requires confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path in bucket"},
                    "confirm": {"type": "boolean", "default": False},
                },
                "required": ["path", "confirm"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        init_firebase()
        from firebase_admin import firestore, auth, storage

        db = firestore.client()

        # --- Firestore ---
        if name == "firestore_get":
            path = validate_path(arguments["path"])
            doc = db.document(path).get()
            if doc.exists:
                result = json.dumps(serialize_doc(doc), indent=2, default=str)
            else:
                result = f"Document not found: {path}"

        elif name == "firestore_query":
            collection = validate_path(arguments["collection"])
            query = db.collection(collection)

            for w in arguments.get("where", []):
                field = sanitize(w["field"], 100)
                op = w["op"]
                allowed_ops = {"==", "!=", "<", "<=", ">", ">=", "in", "not-in", "array-contains", "array-contains-any"}
                if op not in allowed_ops:
                    return [TextContent(type="text", text=f"ERROR: Invalid operator: {op}")]
                query = query.where(field, op, w["value"])

            order_by = arguments.get("order_by", "")
            if order_by:
                order_by = sanitize(order_by, 100)
                direction = firestore.Query.DESCENDING if arguments.get("order_dir") == "desc" else firestore.Query.ASCENDING
                query = query.order_by(order_by, direction=direction)

            limit = min(arguments.get("limit", 50), MAX_RESULTS)
            docs = query.limit(limit).stream()
            results = [serialize_doc(d) for d in docs]
            result = json.dumps({"count": len(results), "documents": results}, indent=2, default=str)

        elif name == "firestore_list_collections":
            parent = arguments.get("parent_path", "")
            if parent:
                parent = validate_path(parent)
                collections = db.document(parent).collections()
            else:
                collections = db.collections()
            names = [c.id for c in collections]
            result = json.dumps({"collections": names}, indent=2)

        elif name == "firestore_set":
            if not arguments.get("confirm"):
                return [TextContent(type="text", text="BLOCKED: Set confirm=true to execute write operation.")]
            path = validate_path(arguments["path"])
            data = arguments["data"]
            merge = arguments.get("merge", True)
            db.document(path).set(data, merge=merge)
            result = f"Document written: {path} (merge={merge})"

        elif name == "firestore_delete":
            if not arguments.get("confirm"):
                return [TextContent(type="text", text="BLOCKED: Set confirm=true to execute delete operation.")]
            path = validate_path(arguments["path"])
            db.document(path).delete()
            result = f"Document deleted: {path}"

        elif name == "firestore_count":
            collection = validate_path(arguments["collection"])
            query = db.collection(collection)
            for w in arguments.get("where", []):
                field = sanitize(w["field"], 100)
                query = query.where(field, w["op"], w["value"])
            # Count via aggregation (Firestore supports count())
            try:
                count_query = query.count()
                count_result = count_query.get()
                count = count_result[0][0].value
                result = json.dumps({"collection": collection, "count": count})
            except Exception:
                # Fallback: stream and count
                docs = list(query.limit(MAX_RESULTS).stream())
                result = json.dumps({"collection": collection, "count": len(docs), "note": "fallback count, capped at 500"})

        # --- Auth ---
        elif name == "auth_get_user":
            uid = arguments.get("uid", "")
            email = arguments.get("email", "")
            if uid:
                user = auth.get_user(sanitize(uid, 200))
            elif email:
                user = auth.get_user_by_email(sanitize(email, 200))
            else:
                return [TextContent(type="text", text="ERROR: Provide uid or email")]
            result = json.dumps({
                "uid": user.uid,
                "email": user.email,
                "display_name": user.display_name,
                "phone": user.phone_number,
                "disabled": user.disabled,
                "email_verified": user.email_verified,
                "custom_claims": user.custom_claims,
                "creation_time": user.user_metadata.creation_timestamp,
                "last_sign_in": user.user_metadata.last_sign_in_timestamp,
                "providers": [p.provider_id for p in user.provider_data],
            }, indent=2, default=str)

        elif name == "auth_list_users":
            limit = min(arguments.get("limit", 50), MAX_RESULTS)
            page_token = arguments.get("page_token", "") or None
            page = auth.list_users(max_results=limit, page_token=page_token)
            users = []
            for user in page.users:
                users.append({
                    "uid": user.uid,
                    "email": user.email,
                    "display_name": user.display_name,
                    "disabled": user.disabled,
                })
            result = json.dumps({
                "count": len(users),
                "users": users,
                "next_page_token": page.next_page_token,
            }, indent=2, default=str)

        elif name == "auth_set_custom_claims":
            if not arguments.get("confirm"):
                return [TextContent(type="text", text="BLOCKED: Set confirm=true to modify user claims.")]
            uid = sanitize(arguments["uid"], 200)
            claims = arguments["claims"]
            auth.set_custom_claims(uid, claims)
            result = f"Custom claims set for user {uid}: {json.dumps(claims)}"

        # --- Storage ---
        elif name == "storage_list":
            bucket = storage.bucket()
            prefix = arguments.get("prefix", "")
            if prefix:
                prefix = sanitize(prefix, 500)
            limit = min(arguments.get("limit", 100), MAX_RESULTS)
            blobs = list(bucket.list_blobs(prefix=prefix, max_results=limit))
            files = [{"name": b.name, "size": b.size, "updated": str(b.updated)} for b in blobs]
            result = json.dumps({"count": len(files), "files": files}, indent=2)

        elif name == "storage_get_url":
            bucket = storage.bucket()
            path = sanitize(arguments["path"], 1000)
            blob = bucket.blob(path)
            hours = min(arguments.get("expiration_hours", 1), 168)  # Max 7 days
            from datetime import timedelta
            url = blob.generate_signed_url(expiration=timedelta(hours=hours))
            result = json.dumps({"path": path, "url": url, "expires_in_hours": hours})

        elif name == "storage_delete":
            if not arguments.get("confirm"):
                return [TextContent(type="text", text="BLOCKED: Set confirm=true to delete file.")]
            bucket = storage.bucket()
            path = sanitize(arguments["path"], 1000)
            blob = bucket.blob(path)
            blob.delete()
            result = f"File deleted: {path}"

        else:
            result = f"ERROR: Unknown tool: {name}"

        return [TextContent(type="text", text=truncate(result))]

    except ImportError:
        return [TextContent(type="text", text="ERROR: firebase-admin not installed. Run: pip install firebase-admin")]
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
