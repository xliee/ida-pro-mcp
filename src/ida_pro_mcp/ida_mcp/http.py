import html
import json
import re
import ida_netnode
from urllib.parse import urlparse, parse_qs
from typing import TypeVar, cast
from http.server import HTTPServer

from .sync import idasync
from .rpc import (
    McpRpcRegistry,
    McpHttpRequestHandler,
    MCP_SERVER,
    MCP_UNSAFE,
    get_cached_output,
)


T = TypeVar("T")


@idasync
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        print(
            f"[WARNING] Invalid JSON stored in netnode '{key}': '{json_blob}' from netnode: {e}"
        )
        return default


@idasync
def config_json_set(key: str, value):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    node.setblob(json_blob, 0, "C")


def handle_enabled_tools(registry: McpRpcRegistry, config_key: str):
    """Changed to registry to enable configured tools, returns original tools."""
    original_tools = registry.methods.copy()
    enabled_tools = config_json_get(
        config_key, {name: True for name in original_tools.keys()}
    )
    new_tools = [name for name in original_tools if name not in enabled_tools]

    removed_tools = [name for name in enabled_tools if name not in original_tools]
    if removed_tools:
        for name in removed_tools:
            enabled_tools.pop(name)

    if new_tools:
        enabled_tools.update({name: True for name in new_tools})
        config_json_set(config_key, enabled_tools)

    registry.methods = {
        name: func for name, func in original_tools.items() if enabled_tools.get(name)
    }
    return original_tools


DEFAULT_CORS_POLICY = "local"


DEFAULT_BIND_HOST = "127.0.0.1"


def get_cors_policy(port: int) -> str:
    """Retrieve the current CORS policy from configuration."""
    bind_host = config_json_get("bind_host", DEFAULT_BIND_HOST)
    extra = set()
    if bind_host not in ("127.0.0.1", "localhost", "0.0.0.0", "::"):
        extra.add(bind_host)
    match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
        case "unrestricted":
            return "*"
        case "local":
            hosts = "127.0.0.1 localhost"
            return f"{hosts} {' '.join(extra)}" if extra else hosts
        case "direct":
            origins = [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]
            origins.extend(f"http://{h}:{port}" for h in extra)
            return " ".join(origins)
        case _:
            return "*"


ORIGINAL_TOOLS = handle_enabled_tools(MCP_SERVER.tools, "enabled_tools")


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.update_cors_policy()

    def _cors_local(self, origin: str) -> bool:
        """Allow CORS from localhost and the bound host on any port."""
        allowed = {"localhost", "127.0.0.1", "::1"}
        h = self.bound_host
        if h not in ("0.0.0.0", "::"):
            allowed.add(h)
        return urlparse(origin).hostname in allowed

    def update_cors_policy(self):
        match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
            case "unrestricted":
                self.mcp_server.cors_allowed_origins = "*"
            case "local":
                self.mcp_server.cors_allowed_origins = self._cors_local
            case "direct":
                self.mcp_server.cors_allowed_origins = None

    def do_POST(self):
        """Handles POST requests."""
        if urlparse(self.path).path == "/config":
            if not self._check_origin():
                return
            self._handle_config_post()
        else:
            super().do_POST()

    def do_GET(self):
        """Handles GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/config.html":
            if not self._check_host():
                return
            self._handle_config_get()
            return

        # Handle output download requests
        output_match = re.match(r"^/output/([a-f0-9-]+)\.(\w+)$", path)
        if output_match:
            self._handle_output_download(output_match.group(1), output_match.group(2))
            return

        super().do_GET()

    def _handle_output_download(self, output_id: str, extension: str):
        """Handle download of cached output data."""
        data = get_cached_output(output_id)
        if data is None:
            self.send_error(404, "Output not found or expired")
            return

        if extension == "json":
            content = json.dumps(data, indent=2)
        elif isinstance(data, dict) and "code" in data:
            content = str(data["code"])
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            content = "\n\n".join(
                str(item.get("code", item.get("asm", item.get("lines", ""))))
                for item in data
            )
        else:
            content = json.dumps(data, indent=2)

        body = content.encode("utf-8")
        self.send_response(200)
        content_type = "application/json" if extension == "json" else "text/plain"
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", f'attachment; filename="{output_id}.{extension}"'
        )
        self.end_headers()
        self.wfile.write(body)

    @property
    def server_port(self) -> int:
        return cast(HTTPServer, self.server).server_port

    @property
    def bound_host(self) -> str:
        """The address the server is actually bound to."""
        addr = cast(HTTPServer, self.server).server_address[0]
        return str(addr)

    def _allowed_hosts(self) -> set[str]:
        """Hostnames accepted by origin / host header checks."""
        hosts = {"127.0.0.1", "localhost"}
        h = self.bound_host
        if h not in ("0.0.0.0", "::"):
            hosts.add(h)
        return hosts

    def _check_origin(self) -> bool:
        """
        Prevents CSRF and DNS rebinding attacks by ensuring POST requests
        originate from pages served by this server, not external websites.
        """
        origin = self.headers.get("Origin")
        port = self.server_port
        allowed = {f"http://{h}:{port}" for h in self._allowed_hosts()}
        if origin not in allowed:
            self.send_error(403, "Invalid Origin")
            return False
        return True

    def _check_host(self) -> bool:
        """
        Prevents DNS rebinding attacks where an attacker's domain (e.g., evil.com)
        resolves to 127.0.0.1, allowing their page to read localhost resources.
        """
        host = self.headers.get("Host")
        port = self.server_port
        allowed = {f"{h}:{port}" for h in self._allowed_hosts()}
        if host not in allowed:
            self.send_error(403, "Invalid Host")
            return False
        return True

    def _send_html(self, status: int, text: str):
        """
        Prevents clickjacking by blocking iframes (X-Frame-Options for older
        browsers, frame-ancestors for modern ones). Other CSP directives
        provide defense-in-depth against content injection attacks.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "; ".join(
                [
                    "frame-ancestors 'none'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "default-src 'self'",
                    "form-action 'self'",
                ]
            ),
        )
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_get(self):
        """Sends the configuration page with checkboxes."""
        cors_policy = config_json_get("cors_policy", DEFAULT_CORS_POLICY)

        body = """<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP Config</title>
  <style>
:root {
  --bg: #ffffff;
  --text: #1a1a1a;
  --border: #e0e0e0;
  --accent: #0066cc;
  --hover: #f5f5f5;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a1a;
    --text: #e0e0e0;
    --border: #333333;
    --accent: #4da6ff;
    --hover: #2a2a2a;
  }
}

* {
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  max-width: 800px;
  margin: 2rem auto;
  padding: 1rem;
  line-height: 1.4;
}

h1 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}

h2 {
  font-size: 1.1rem;
  margin-top: 1.5rem;
  margin-bottom: 0.5rem;
}

label {
  display: block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
}

label:hover {
  background: var(--hover);
}

input[type="checkbox"],
input[type="radio"] {
  margin-right: 0.5rem;
  accent-color: var(--accent);
}

input[type="submit"] {
  margin-top: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

input[type="submit"]:hover {
  opacity: 0.9;
}

.tooltip {
  border-bottom: 1px dotted var(--text);
}
  </style>
  <script defer>
  function setTools(mode) {
    document.querySelectorAll('input[data-tool]').forEach(cb => {
        if (mode === 'all') cb.checked = true;
        else if (mode === 'none') cb.checked = false;
        else if (mode === 'disable-unsafe' && cb.hasAttribute('data-unsafe')) cb.checked = false;
    });
  }
  </script>
</head>
<body>
<h1>IDA Pro MCP Config</h1>

<form method="post" action="/config">

<h2>API Access</h2>
"""
        cors_options = [
            (
                "unrestricted",
                "⛔ Unrestricted",
                "Any website can make requests to this server. A malicious site you visit could access or modify your IDA database.",
            ),
            (
                "local",
                "🏠 Local apps only",
                "Only web apps running on localhost can connect. Remote websites are blocked, but local development tools work.",
            ),
            (
                "direct",
                "🔒 Direct connections only",
                "Browser-based requests are blocked. Only direct clients like curl, MCP tools, or Claude Desktop can connect.",
            ),
        ]
        for value, label, tooltip in cors_options:
            checked = "checked" if cors_policy == value else ""
            body += f'<label><input type="radio" name="cors_policy" value="{html.escape(value)}" {checked}><span class="tooltip" title="{html.escape(tooltip)}">{html.escape(label)}</span></label>'

        bind_host = config_json_get("bind_host", DEFAULT_BIND_HOST)
        body += "<h2>Bind Address</h2>"
        body += '<p style="font-size: 0.85rem; margin: 0.25rem 0 0.5rem;">'
        body += 'Address the server listens on. Use <code>127.0.0.1</code> for localhost only, '
        body += 'a LAN IP for remote access, or <code>0.0.0.0</code> for all interfaces. '
        body += '<strong>Applied on next server restart.</strong></p>'
        body += f'<label style="display:inline-flex;align-items:center;gap:0.5rem;">'
        body += f'<input type="text" name="bind_host" value="{html.escape(bind_host)}" '
        body += 'style="padding:0.3rem 0.5rem;border:1px solid var(--border);border-radius:4px;'
        body += 'background:var(--bg);color:var(--text);font-family:monospace;"></label>'

        body += "<br><input type='submit' value='Save'>"

        quick_select = """<p style="font-size: 0.9rem; margin: 0.5rem 0;">
  Select:
  <a href="#" onclick="setTools('all'); return false;">All</a> ·
  <a href="#" onclick="setTools('none'); return false;">None</a> ·
  <a href="#" onclick="setTools('disable-unsafe'); return false;">Disable unsafe</a>
</p>"""

        body += "<h2>Enabled Tools</h2>"
        body += quick_select
        for name, func in ORIGINAL_TOOLS.items():
            description = (
                (func.__doc__ or "No description").strip().splitlines()[0].strip()
            )
            unsafe_prefix = "⚠️ " if name in MCP_UNSAFE else ""
            checked = " checked" if name in self.mcp_server.tools.methods else ""
            unsafe_attr = " data-unsafe" if name in MCP_UNSAFE else ""
            body += f"<label><input type='checkbox' name='{html.escape(name)}' value='{html.escape(name)}'{checked}{unsafe_attr} data-tool>{unsafe_prefix}{html.escape(name)}: {html.escape(description)}</label>"
        body += quick_select
        body += "<br><input type='submit' value='Save'>"
        body += "</form></body></html>"
        self._send_html(200, body)

    def _handle_config_post(self):
        """Handles the configuration form submission."""
        # Validate Content-Type
        content_type = self.headers.get("content-type", "").split(";")[0].strip()
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(400, f"Unsupported Content-Type: {content_type}")
            return

        # Parse the form data
        length = int(self.headers.get("content-length", "0"))
        postvars = parse_qs(self.rfile.read(length).decode("utf-8"))

        # Update CORS policy
        cors_policy = postvars.get("cors_policy", [DEFAULT_CORS_POLICY])[0]
        config_json_set("cors_policy", cors_policy)
        self.update_cors_policy()

        # Update bind host (applied on next server restart)
        bind_host = postvars.get("bind_host", [DEFAULT_BIND_HOST])[0].strip()
        if not re.match(r"^[\w\.\:\-]+$", bind_host):
            self.send_error(400, "Invalid bind host")
            return
        config_json_set("bind_host", bind_host)

        # Update the server's tools
        enabled_tools = {name: name in postvars for name in ORIGINAL_TOOLS.keys()}
        self.mcp_server.tools.methods = {
            name: func
            for name, func in ORIGINAL_TOOLS.items()
            if enabled_tools.get(name)
        }
        config_json_set("enabled_tools", enabled_tools)

        # Redirect back to the config page
        self.send_response(302)
        self.send_header("Location", "/config.html")
        self.end_headers()
