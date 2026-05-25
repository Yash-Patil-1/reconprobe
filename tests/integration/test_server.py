"""Local test HTTP server for ReconProbe integration tests.

Provides configurable HTTP/HTTPS endpoints that simulate real-world services,
allowing integration tests to verify ReconProbe's features against actual
running services rather than mocked connections.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import ssl
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

logger = logging.getLogger(__name__)

# ── Self-signed cert generation (inline, no external deps) ────────────

def _generate_self_signed_cert(cert_path: str, key_path: str) -> None:
    """Generate a self-signed certificate for testing TLS.
    
    Uses cryptography if available, otherwise falls back to openssl subprocess.
    """
    import subprocess
    import tempfile
    
    # Generate using openssl
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path,
        "-out", cert_path,
        "-days", "365",
        "-nodes",
        "-subj", "/C=US/ST=Test/L=Test/O=ReconProbe/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to generate self-signed cert: {result.stderr}")
    logger.info("Generated self-signed cert: %s, %s", cert_path, key_path)


# ── Test HTTP Request Handler ─────────────────────────────────────────

class IntegrationHTTPHandler(BaseHTTPRequestHandler):
    """Configurable HTTP request handler for integration tests.
    
    Responds with predefined content mimicking real web services.
    Supports configurable headers, status codes, and response bodies
    via a shared config dict.
    """
    
    # Shared configuration set by the test server
    config: dict = {}
    
    def log_message(self, format: str, *args) -> None:
        """Suppress default HTTP server logging in tests."""
        pass
    
    def _get_server_headers(self) -> dict:
        """Return server-specific headers based on test configuration."""
        return self.config.get("server_headers", {})
    
    def _get_tech_headers(self) -> dict:
        """Return technology fingerprinting headers."""
        return self.config.get("tech_headers", {})
    
    def _get_waf_headers(self) -> dict:
        """Return WAF-related headers for testing WAF detection."""
        return self.config.get("waf_headers", {})
    
    def _get_security_headers(self) -> dict:
        """Return security-related headers for SSL audit testing."""
        return self.config.get("security_headers", {})
    
    def _get_waf_trigger_paths(self) -> list[str]:
        """Return paths that should trigger WAF-like responses."""
        return self.config.get("waf_trigger_paths", [])
    
    def _get_custom_endpoints(self) -> dict:
        """Return custom endpoint configurations."""
        return self.config.get("custom_endpoints", {})
    
    def _check_waf_trigger(self) -> Optional[dict]:
        """Check if the request path should trigger a WAF-like response."""
        path = self.path.split("?")[0].lower()
        waf_paths = self._get_waf_trigger_paths()
        if any(wp in path for wp in waf_paths):
            return {
                "status": 403,
                "headers": self._get_waf_headers(),
                "body": "<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF</p></body></html>",
            }
        return None
    
    def _respond(self, status: int, body: str, content_type: str = "text/html",
                 extra_headers: Optional[dict] = None) -> None:
        """Send a response with the given status, body, and headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        
        # Add server headers
        for key, value in self._get_server_headers().items():
            self.send_header(key, value)
        
        # Add tech headers
        for key, value in self._get_tech_headers().items():
            self.send_header(key, value)
        
        # Add security headers
        for key, value in self._get_security_headers().items():
            self.send_header(key, value)
        
        # Add WAF headers (so WAF detection tests work on normal requests)
        for key, value in self._get_waf_headers().items():
            self.send_header(key, value)
        
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())
    
    def _respond_json(self, status: int, data: dict) -> None:
        """Send a JSON response."""
        self._respond(status, json.dumps(data), "application/json")
    
    def _handle_api(self, path: str) -> None:
        """Handle API-like endpoints."""
        if path == "/api/health":
            self._respond_json(200, {"status": "ok", "uptime": 3600})
        elif path == "/api/users":
            self._respond_json(200, {
                "users": [
                    {"id": 1, "name": "admin", "email": "admin@test.local"},
                    {"id": 2, "name": "user", "email": "user@test.local"},
                ]
            })
        elif path == "/api/config":
            self._respond_json(200, {
                "api_key": "sk-test-api-key-12345",
                "db_host": "internal-db.test.local",
                "secret": "super-secret-config-value",
            })
        elif path.startswith("/api/"):
            self._respond_json(404, {"error": "not_found"})
    
    def _handle_admin(self, path: str) -> None:
        """Handle admin-like endpoints."""
        if path == "/admin":
            self._respond(200, "<html><body><h1>Admin Panel</h1>"
                                "<form method='POST'><input name='user'/><input name='pass'/></form>"
                                "</body></html>")
        elif path == "/admin/login":
            self._respond(200, "<html><body><h1>Login</h1></body></html>")
        elif path == "/admin/config.php":
            self._respond(200, "<?php\n$db_pass = 'admin_password_123';\n?>",
                         content_type="text/plain")
        elif path == "/admin/backup.sql":
            self._respond(200, "INSERT INTO users VALUES (1, 'admin', 'password123');\n",
                         content_type="text/plain")
    
    def _handle_assets(self, path: str) -> None:
        """Handle static asset endpoints."""
        if path.endswith(".js"):
            self._respond(200, "console.log('test');", "application/javascript")
        elif path.endswith(".css"):
            self._respond(200, "body { color: red; }", "text/css")
        elif path.endswith(".png"):
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            for key, value in self._get_server_headers().items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)  # Minimal PNG
    
    def _handle_crawl_paths(self, path: str) -> None:
        """Handle paths used for crawling tests."""
        if path == "/":
            self._respond(200, """<html>
<head><title>Home Page</title></head>
<body>
    <h1>Welcome to Test Site</h1>
    <a href="/about">About</a>
    <a href="/contact">Contact</a>
    <a href="/products">Products</a>
    <a href="https://external.example.com">External Link</a>
    <form action="/login" method="POST">
        <input type="text" name="username"/>
        <input type="password" name="password"/>
    </form>
    <script src="/static/app.js"></script>
</body>
</html>""")
        elif path == "/about":
            self._respond(200, """<html>
<head><title>About Us</title></head>
<body><h1>About Us</h1><a href="/team">Team</a><a href="/">Home</a></body>
</html>""")
        elif path == "/contact":
            self._respond(200, """<html>
<head><title>Contact</title></head>
<body><h1>Contact</h1><p>Email: admin@test.local</p></body>
</html>""")
        elif path == "/products":
            self._respond(200, """<html>
<head><title>Products</title></head>
<body><h1>Products</h1><a href="/product/1">Product 1</a></body>
</html>""")
        elif path == "/product/1":
            self._respond(200, """<html>
<head><title>Product 1</title></head>
<body><h1>Product 1 Details</h1></body>
</html>""")

    def _handle_dirs(self, path: str) -> None:
        """Handle paths used for directory brute-force testing."""
        dir_map = {
            "/admin": ("Admin Panel", "p1q2r3s4t5u6v7w8x9y0"),
            "/login": ("Login Page", "a1b2c3d4e5f6g7h8i9j0"),
            "/dashboard": ("Dashboard", "k0l1m2n3o4p5q6r7s8t9"),
            "/wp-admin": ("WordPress Admin", "u0v1w2x3y4z5a6b7c8d9"),
            "/backup": ("Backup Available", "e0f1g2h3i4j5k6l7m8n9"),
            "/config": ("Configuration", "o0p1q2r3s4t5u6v7w8x9"),
            "/.git": ("Git Repository", "y0z1a2b3c4d5e6f7g8h9"),
            "/.env": ("Environment File", "i0j1k2l3m4n5o6p7q8r9"),
        }
        if path in dir_map:
            title, token = dir_map[path]
            body = (
                f"<html><body><h1>{title}</h1>"
                f"<p>This is a unique real page with distinct content to avoid "
                f"being filtered by smart 404 detection. Unique token: {token}.</p>"
                f"<a href=\"/page/about\">About</a>"
                f"<a href=\"/page/contact\">Contact</a>"
                f"</body></html>"
            )
            self._respond(200, body)

    def do_GET(self):
        """Handle GET requests."""
        path = self.path.split("?")[0]
        
        # Check WAF triggers
        waf_response = self._check_waf_trigger()
        if waf_response:
            self._respond(waf_response["status"], waf_response["body"],
                         extra_headers=waf_response.get("headers"))
            return
        
        # Check custom endpoints
        custom = self._get_custom_endpoints()
        if path in custom:
            ep = custom[path]
            self._respond(ep.get("status", 200), ep.get("body", ""),
                         ep.get("content_type", "text/html"),
                         ep.get("headers", {}))
            return
        
        # Route to handlers
        if path.startswith("/api/"):
            self._handle_api(path)
        elif path.startswith("/admin/"):
            self._handle_admin(path)
        elif path.startswith("/static/") or path.endswith((".js", ".css", ".png", ".jpg", ".ico")):
            self._handle_assets(path)
        elif path == "/" or path.startswith("/about") or path.startswith("/contact") or path.startswith("/product"):
            self._handle_crawl_paths(path)
        elif path in ("/admin", "/login", "/dashboard", "/wp-admin", "/backup", "/config", "/.git", "/.env"):
            self._handle_dirs(path)
        else:
            self._respond(404, "<html><body><h1>404 Not Found</h1></body></html>")
    
    def do_POST(self):
        """Handle POST requests."""
        path = self.path.split("?")[0]
        
        if path == "/login":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode() if content_length > 0 else ""
            if "admin" in body and "admin" in body:
                self._respond(200, "<html><body><h1>Welcome, admin!</h1></body></html>")
            else:
                self._respond(401, "<html><body><h1>Unauthorized</h1></body></html>")
        elif path == "/api/login":
            self._respond_json(200, {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"})
        else:
            self._respond(404, "<html><body><h1>404 Not Found</h1></body></html>")

    # Silence warning noise
    do_HEAD = do_GET


# ── Default configuration presets ─────────────────────────────────────

DEFAULT_SERVER_HEADERS = {
    "Server": "nginx/1.24.0",
    "X-Powered-By": "PHP/8.2.0",
}

DEFAULT_TECH_HEADERS = {
    "X-Generator": "Drupal 10 (https://www.drupal.org)",
    "X-Drupal-Cache": "HIT",
}

DEFAULT_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

DEFAULT_WAF_HEADERS = {
    "X-Sucuri-ID": "13000",
    "X-Sucuri-Cache": "MISS",
    "X-Sucuri-Request-Id": "test-waf-request-001",
    "CF-Cache-Status": "DYNAMIC",
    "CF-Ray": "test-cf-ray-001",
}

WAF_TRIGGER_PATHS = [
    "/../../etc/passwd",
    "/?id=1' OR '1'='1",
    "/?q=<script>alert(1)</script>",
    "/union/select/",
    "/admin?cmd=cat+/etc/passwd",
]


def get_default_config() -> dict:
    """Return the default test server configuration."""
    return {
        "server_headers": DEFAULT_SERVER_HEADERS,
        "tech_headers": DEFAULT_TECH_HEADERS,
        "security_headers": DEFAULT_SECURITY_HEADERS,
        "waf_headers": DEFAULT_WAF_HEADERS,
        "waf_trigger_paths": WAF_TRIGGER_PATHS,
        "custom_endpoints": {},
    }


# ── Test Server Manager ───────────────────────────────────────────────

class IntegrationTestServer:
    """Manages a local HTTP/HTTPS test server for integration tests.
    
    Usage:
        server = IntegrationTestServer(port=8080)
        server.start()
        # Run tests against localhost:8080
        server.stop()
    """
    
    def __init__(
        self,
        http_port: int = 0,
        https_port: int = 0,
        config: Optional[dict] = None,
        cert_dir: Optional[str] = None,
    ):
        self.http_port = http_port or self._find_free_port()
        self.https_port = https_port or self._find_free_port()
        self.config = config or get_default_config()
        self.cert_dir = cert_dir or "/tmp/reconprobe_test_certs"
        self._http_server: Optional[HTTPServer] = None
        self._https_server: Optional[HTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._https_thread: Optional[threading.Thread] = None
        self._running = False
    
    @staticmethod
    def _find_free_port() -> int:
        """Find a free TCP port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
    
    def start(self) -> None:
        """Start the HTTP and HTTPS servers."""
        if self._running:
            return
        
        # Set up handler config
        IntegrationHTTPHandler.config = self.config
        
        # Start HTTP server
        self._http_server = HTTPServer(("127.0.0.1", self.http_port), IntegrationHTTPHandler)
        self._http_thread = threading.Thread(
            target=self._http_server.serve_forever,
            daemon=True,
            name="test-http-server",
        )
        self._http_thread.start()
        logger.info("Test HTTP server started on 127.0.0.1:%d", self.http_port)
        
        # Start HTTPS server if cert generation succeeds
        try:
            os.makedirs(self.cert_dir, exist_ok=True)
            cert_path = os.path.join(self.cert_dir, "server.crt")
            key_path = os.path.join(self.cert_dir, "server.key")
            
            if not (os.path.exists(cert_path) and os.path.exists(key_path)):
                _generate_self_signed_cert(cert_path, key_path)
            
            self._https_server = HTTPServer(("127.0.0.1", self.https_port), IntegrationHTTPHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._https_server.socket = ctx.wrap_socket(
                self._https_server.socket, server_side=True
            )
            self._https_thread = threading.Thread(
                target=self._https_server.serve_forever,
                daemon=True,
                name="test-https-server",
            )
            self._https_thread.start()
            logger.info("Test HTTPS server started on 127.0.0.1:%d", self.https_port)
        except (RuntimeError, FileNotFoundError, ImportError) as e:
            logger.warning("HTTPS server not started: %s", e)
        
        self._running = True
    
    def stop(self) -> None:
        """Stop the servers."""
        self._running = False
        if self._http_server:
            self._http_server.shutdown()
        if self._https_server:
            self._https_server.shutdown()
        logger.info("Test servers stopped")
    
    def get_http_url(self, path: str = "/") -> str:
        """Get the full HTTP URL for a path on the test server."""
        return f"http://127.0.0.1:{self.http_port}{path}"
    
    def get_https_url(self, path: str = "/") -> str:
        """Get the full HTTPS URL for a path on the test server."""
        return f"https://127.0.0.1:{self.https_port}{path}"
    
    def update_config(self, config_updates: dict) -> None:
        """Update the server configuration."""
        self.config.update(config_updates)
        IntegrationHTTPHandler.config = self.config
    
    def __enter__(self) -> "IntegrationTestServer":
        self.start()
        return self
    
    def __exit__(self, *args) -> None:
        self.stop()
