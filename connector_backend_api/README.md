# Connector Backend API

Run
- Local dev: `UVICORN_RELOAD=1 python -m connector_backend_api.run` (binds to 0.0.0.0:3001)
- Override host/port if needed: `UVICORN_HOST=0.0.0.0 UVICORN_PORT=3001 python -m connector_backend_api.run`

Environment
- MONGODB_URI, MONGODB_DB (required for DB-backed routes). If missing, the service still starts for health checks.
- ENCRYPTION_KEY (optional) base64-url-safe 32-byte key for encrypting token fields.
- OAUTH_REDIRECT_BASE_URL (optional) used by provider services to construct callback URLs.
- LLM_PROXY_URL / LLM_PROXY_KEY (optional) for /llm-proxy.

Headers:
- X-Tenant-ID: required
- X-User-ID: optional (some endpoints also require user_id in body)
- X-Connector-Key: optional; used by auth guard

Endpoints:
- POST /auth/api-key
- POST /auth/oauth/start
- POST /auth/oauth/callback
- GET  /connectors
- POST /connectors/{key}
- POST /search
- POST /create
- GET  /projects?connector_key=...&user_id=...
- GET  /spaces?connector_key=...&user_id=...
- POST /llm-proxy
- GET  /healthz

Responses are wrapped as:
{ "status": "ok", "data": ... }
Errors are:
{ "status": "error", "error": { "code": "...", "message": "..." } }
