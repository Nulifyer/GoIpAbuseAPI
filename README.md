# AbuseIPDB ForwardAuth Checker

A small Go service that acts as a **Traefik ForwardAuth** middleware.  
It checks the client IP against **AbuseIPDB**, caches results in **Valkey/Redis**, and blocks requests if the abuse score meets or exceeds a configured threshold.

## Features
- ForwardAuth endpoint (`/check`)
- AbuseIPDB lookup with configurable max age
- Cache results in Valkey/Redis
- CIDR allowlist bypass (skip checks)
- Text or structured JSON logs
- Optional Prometheus metrics on a separate listener
- Coalesced concurrent lookups for the same IP
- Adds response headers:
  - `X-Abuse-Decision`
  - `X-Abuse-Source`
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
| `LOG_FORMAT` | ❌ | `text` | Log format: `text` or `json` |
| `METRICS_ENABLED` | ❌ | `false` | Enable the separate Prometheus metrics listener |
| `METRICS_ADDR` | ❌ | `:9090` | Metrics listener address |

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
          - "X-Abuse-Decision"
          - "X-Abuse-Source"
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
- Concurrent cache misses for the same IP share one AbuseIPDB request.

## Decision Logs

Decision logs include the original host, method, sanitized path, result source, score, and report count. Query parameters and fragments are removed from logged paths.

```json
{"client_ip":"203.0.113.10","decision":"blocked","duration_ms":1.42,"event":"auth_decision","host":"example.com","level":"WARN","method":"GET","path":"/login","reports":42,"score":100,"source":"cache","status":403,"threshold":25,"timestamp":"2026-08-03T12:00:00Z"}
```

Sources are `api`, `cache`, or `cidr`. Request, cache, API, and internal failures use the `request`, `cache`, `api`, or `service` source respectively.

## Prometheus Metrics

When `METRICS_ENABLED=true`, the service exposes `/metrics` and `/-/healthy` on `METRICS_ADDR`. Keep this listener on an internal container network and do not publish it directly.

```yaml
scrape_configs:
  - job_name: goipabuseapi
    static_configs:
      - targets: ["abuseipdb-auth:9090"]
```

Metrics include:

- `goipabuse_decisions_total{decision,source}`
- `goipabuse_cache_operations_total{operation,result}`
- `goipabuse_api_requests_total{result}`
- `goipabuse_api_request_duration_seconds`
- `goipabuse_request_duration_seconds{decision,source}`
- `goipabuse_singleflight_shared_results_total`
- `goipabuse_requests_in_flight`
- `goipabuse_score`

IP addresses, hosts, paths, and user agents are deliberately excluded from metric labels to prevent unbounded cardinality. Use structured logs for per-IP and per-request analysis.

GeoIP and crawler classification are intentionally left to the downstream log pipeline. Keeping those lookups out of the ForwardAuth request path avoids DNS, feed-refresh, and geolocation failures affecting request authorization.
