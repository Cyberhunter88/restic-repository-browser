from __future__ import annotations

import os
import ssl
import urllib.request


scheme = "https" if os.environ.get("RRB_TLS_MODE", "proxy") == "files" else "http"
port = os.environ.get("RRB_HTTP_PORT", "8080")
context = ssl._create_unverified_context() if scheme == "https" else None
urllib.request.urlopen(
    f"{scheme}://127.0.0.1:{port}/api/health/ready",
    context=context,
    timeout=5,
).read()

