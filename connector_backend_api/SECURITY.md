# Backend Security Hardening Notes

This document summarizes the security posture and improvements implemented for the Connector Backend API.

Highlights:
- Standard security headers middleware:
  - Strict-Transport-Security (when SITE_URL is https and ENVIRONMENT != development)
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - Referrer-Policy: no-referrer
  - Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
- Rate limiting:
  - Global per-route rate limiting via SlowAPI middleware
  - Additional in-memory (per-tenant, provider, route) limiter for sensitive operations (core.errors.rate_limit_check)
- Tenant and auth:
  - TenantContext extracted from configurable header (TENANT_HEADER_NAME) or JWT claims.
  - Enforce tenant match (403) for all routes that receive tenant_id.
  - Authorize connection access hook present (extend to RBAC).
  - Sensitive endpoints use coarse-grained per-user or per-tenant rate keys.
- OAuth state:
  - Signed state using JWT (HS256) with TTL (JWT_STATE_TTL_SECONDS).
- Secrets handling:
  - No secrets hardcoded. All secrets and configuration come from environment variables.
  - AES-GCM encryption for stored tokens with Additional Authenticated Data (A A D) binding to tenant/connection.
- Bug fix:
  - Removed a synchronous /auth/apikey stub that raised 500. Only the async handler remains.

Operational guidance:
- Ensure ENCRYPTION_KEY is set to a base64-encoded 32-byte value (AES-256).
- Set JWT_STATE_SECRET to a strong random string. In production, consider separate secrets for app JWTs vs OAuth state.
- For production, restrict CORS (CORS_ALLOW_ORIGINS) and disable allow-all headers/methods as appropriate.
- Consider moving rate limit state to a distributed store (e.g., Redis) if running multiple replicas.

JWT/session validation:
- For MVP, Authorization: Bearer <token> is decoded using JWT_ALGORITHM and JWT_STATE_SECRET.
- Claims used: tenant_id (optional), sub/user_id, email, roles.
- Extend to use issuer/audience/keys (JWKS) per your identity provider.

Security headers:
- Injected by src.core.middleware.SecurityHeadersMiddleware and registered in app startup.

Testing recommendations:
- Add tests that:
  - Verify 429 when exceeding limits.
  - Verify 403 on tenant mismatch.
  - Verify security headers exist on responses.
  - Verify encryption/decryption fails when AAD does not match.

Change log:
- 2025-09-29: Introduced SecurityHeadersMiddleware, normalized tenant header handling, removed sync /auth/apikey stub, reinforced rate-limits and error sanitization.
