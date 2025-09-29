# Connector Backend API

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

Responses are wrapped as:
{ "status": "ok", "data": ... }
Errors are:
{ "status": "error", "error": { "code": "...", "message": "..." } }
