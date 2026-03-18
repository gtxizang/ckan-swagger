# CKAN Swagger UX

Interactive API explorer for any CKAN DataStore resource. Paste a CKAN resource URL and get a fully interactive Swagger UI with live schema introspection, enum dropdowns, and SQL query support.

## Quick Start

```bash
docker compose up -d
```

The service will be available at `http://localhost:8080`.

## Production Deployment

### 1. Build and run

```bash
docker compose up -d --build
```

### 2. Reverse proxy (nginx/Caddy/Traefik)

The container serves on port 80 (mapped to 8080 by default). Place it behind your reverse proxy with TLS termination.

Example Caddy config:
```
ckan-swagger.regexflow.com {
    reverse_proxy localhost:8080
}
```

### 3. CORS on CKAN instances

For the explorer to call CKAN APIs from the browser, the CKAN instance must allow cross-origin requests. Add to `ckan.ini`:

```ini
# Option A: Allow all origins (common for public data portals)
ckan.cors.origin_allow_all = true

# Option B: Allow specific origins
ckan.cors.origin_whitelist = https://ckan-swagger.regexflow.com
```

### 4. Link from CKAN

Add a link to your CKAN resource template:

```html
<a href="https://ckan-swagger.regexflow.com/?url={{ full_resource_url }}"
   target="_blank" rel="noopener">
  API Explorer
</a>
```

## Architecture

- **nginx:alpine** serving static files (~2MB total)
- No runtime dependencies, no database, no build step
- All CKAN API calls happen in the user's browser (no server-side proxy)
- Security headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- Health check: `GET /health`

## Configuration

Hidden fields (suppressed from query parameters, visible in Data Dictionary) are configured in `src/app.js`:

```javascript
const DEFAULT_HIDDEN_FIELDS = ["_id", "soda_hashbyte", "soda_identity"];
```

## Security

See `SECURITY.md` for the full security review.

Key points:
- All CKAN-derived content is sanitised before rendering (XSS prevention)
- SQL identifiers are properly escaped (injection prevention)
- URL validation rejects private IPs and non-HTTPS (SSRF prevention)
- Credentials are never stored or transmitted to this service
- CSP headers block inline script execution
- Container runs as non-root user
