"""
Uvicorn entrypoint for the Connector Backend API.

This module explicitly starts the FastAPI app binding to 0.0.0.0:3001 which is
the expected port for container deployments in this project.

Environment:
- UVICORN_HOST (optional): override host (default "0.0.0.0")
- UVICORN_PORT (optional): override port (default 3001)
- UVICORN_RELOAD (optional): set "1" to enable reload for local dev (default off)
"""
from __future__ import annotations

import os
import uvicorn

# Import app from main
from .main import app  # noqa: F401


# PUBLIC_INTERFACE
def main() -> None:
    """Start Uvicorn ASGI server for the FastAPI app."""
    host = os.getenv("UVICORN_HOST", "0.0.0.0")
    # Coerce port to int safely
    port_str = os.getenv("UVICORN_PORT", "3001")
    try:
        port = int(port_str)
    except ValueError:
        port = 3001

    reload_flag = os.getenv("UVICORN_RELOAD", "0") in ("1", "true", "True")

    # Note: app path uses package.module:app notation
    uvicorn.run(
        "connector_backend_api.main:app",
        host=host,
        port=port,
        reload=reload_flag,
        workers=1,
        loop="asyncio",
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
