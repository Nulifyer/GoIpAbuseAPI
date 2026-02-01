# AbuseIPDB ForwardAuth Checker

A small Go service that acts as a **Traefik ForwardAuth** middleware.  
It checks the client IP against **AbuseIPDB**, caches results in **Valkey/Redis**, and blocks requests if the abuse score meets or exceeds a configured threshold.

## Features
- ForwardAuth endpoint (`/check`)
- AbuseIPDB lookup with configurable max age
- Cache results in Valkey/Redis
- CIDR allowlist bypass (skip checks)
- Custom log levels
- Adds response headers:
  - `X-Abuse-Score`
  - `X-Abuse-Reports`

---

## Environment Variables

| Variable | Required | Default | Description |
|---------|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | ✅ | — | AbuseIPDB API key |
| `ABUSE_SCORE_THRESHOLD` | ❌ | `25` | Block if score >= threshold |
| `ABUSEIPDB_MAX_AGE_DAYS` | ❌ | `90` | Max age for AbuseIPDB reports |
| `CACHE_TTL_SECONDS` | ❌ | `3600` | Cache TTL in seconds |
| `VALKEY_URL` | ❌ | `redis://valkey:6379/0` | Valkey/Redis connection URL |
| `PORT` | ❌ | `8080` | Service port |
| `DO_NOT_FORWARD_CIDRS` | ❌ | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7` | CIDRs to skip checks |
| `LOG_LEVEL` | ❌ | `INFO` | `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR` |

---

## Run Locally

```bash
go run .
```

---

## Docker / Podman Build

```bash
podman build -t ghcr.io/<user>/<repo>:latest .
```

---

## ForwardAuth Usage (Traefik)

**Dynamic config example (file provider):**
```yaml
http:
  middlewares:
    abuseipdb-check:
      forwardAuth:
        address: "http://abuseipdb-auth:8080/check"
        authResponseHeaders:
          - "X-Abuse-Score"
          - "X-Abuse-Reports"
```

Attach middleware to routers:
```yaml
http:
  routers:
    app:
      rule: "Host(`example.com`)"
      service: app
      middlewares:
        - abuseipdb-check
```

---

## Behavior
- Requests are checked against AbuseIPDB.
- If the score is **>= threshold**, the request is blocked with `403`.
- Otherwise the request is allowed.
- Cache is used to reduce API calls.
