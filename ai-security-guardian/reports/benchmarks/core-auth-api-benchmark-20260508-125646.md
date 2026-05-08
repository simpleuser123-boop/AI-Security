# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T04:56:41+00:00`
- base_url: `http://127.0.0.1:5097`
- mode: `requests:200`
- workers: `8`
- elapsed_sec: `5.047`
- throughput_rps: `39.63`

## Judgement

- Core API target: `core API P95 < 300ms` -> **FAIL**
- Detection target: `detection segment P95 < 100ms` -> **SKIP**
- Endpoint failures: `{"/api/alerts/types": {"p95_ms": 327.37660000566393, "error_rate": 0.0}, "/api/metrics/traffic": {"p95_ms": 385.42750000488013, "error_rate": 0.0}, "/api/rules": {"p95_ms": 360.6595000019297, "error_rate": 0.0}, "/api/settings": {"p95_ms": 435.5142000131309, "error_rate": 0.0}, "/api/stats": {"p95_ms": 531.7081999965012, "error_rate": 0.0}}`

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 200 | 198.96 | 168.19 | 435.51 | 746.46 | 0.00% | `{"200": 200}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/alerts/types` | 40 | 164.54 | 157.49 | 327.38 | 473.11 | 0.00% | `{"200": 40}` |
| `/api/metrics/traffic` | 40 | 178.76 | 158.98 | 385.43 | 401.32 | 0.00% | `{"200": 40}` |
| `/api/rules` | 40 | 191.21 | 168.19 | 360.66 | 995.50 | 0.00% | `{"200": 40}` |
| `/api/settings` | 40 | 168.59 | 144.57 | 435.51 | 746.46 | 0.00% | `{"200": 40}` |
| `/api/stats` | 40 | 291.71 | 243.09 | 531.71 | 1392.54 | 0.00% | `{"200": 40}` |
