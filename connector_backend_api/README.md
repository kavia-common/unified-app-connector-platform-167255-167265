# Connector Backend API

Backend service managing connectors, authentication (OAuth/API Key), multi-tenant logic, and business logic for interacting with third-party APIs such as Jira and Confluence.

## Run locally

1. Create a virtual environment (optional) and install dependencies:

   pip install -r requirements.txt

2. Set environment variables (copy `.env.example` to `.env` and fill values).

3. Start the server:

   uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

Open http://localhost:8000/docs for interactive API docs.

## Environment variables

See `.env.example`. Important:
- MONGODB_URI, MONGODB_DB_NAME
- JWT_STATE_SECRET (and JWT_ALGORITHM)
- ENCRYPTION_KEY (base64, 16/24/32 bytes)
- TENANT_HEADER_NAME (default: X-Tenant-ID)
- SITE_URL (used for OAuth flows)

## Endpoints overview

- GET /                Health
- /auth
  - POST /auth/apikey            Set/update API key (hashed)
  - POST /auth/apikey/verify     Verify API key
  - POST /auth/oauth/login       Start OAuth login (returns authorize URL + signed state)
  - GET  /auth/oauth/callback    Handle provider callback and exchange code for tokens via headers
  - POST /auth/oauth/refresh     Refresh access token using stored refresh token
- /connectors
  - GET  /connectors                  List registered connectors and descriptors
  - GET  /connectors/{provider}/metadata
  - POST /connectors/search
  - POST /connectors/create
  - GET  /connectors/{provider}/projects
  - GET  /connectors/{provider}/spaces
  - GET  /connectors/tools
  - POST /connectors/tools

## Notes

- This MVP uses in-memory rate limiting per process. Replace with Redis for production.
- Jira/Confluence connectors provided are stubbed and demonstrate shapes and flow. Replace with real HTTP calls and mapping as needed.
- Credentials are stored securely:
  - OAuth tokens encrypted with AES-GCM (ENCRYPTION_KEY)
  - API keys stored as salted HMAC hashes (plaintext never persisted)
