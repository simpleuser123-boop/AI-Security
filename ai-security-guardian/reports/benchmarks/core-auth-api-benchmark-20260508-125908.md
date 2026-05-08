# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T04:59:05+00:00`
- base_url: `http://127.0.0.1:5097`
- mode: `requests:200`
- workers: `8`
- elapsed_sec: `2.949`
- throughput_rps: `67.83`

## Judgement

- Core API target: `core API P95 < 300ms` -> **FAIL**
- Detection target: `detection segment P95 < 100ms` -> **SKIP**
- Endpoint failures: `{"/api/metrics/traffic": {"p95_ms": 371.73160002566874, "error_rate": 0.0}, "/api/rules": {"p95_ms": 389.55219998024404, "error_rate": 0.0}}`

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 200 | 116.66 | 61.42 | 304.44 | 427.96 | 0.00% | `{"200": 200}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/alerts/types` | 40 | 49.64 | 33.70 | 131.00 | 149.53 | 0.00% | `{"200": 40}` |
| `/api/metrics/traffic` | 40 | 215.64 | 200.83 | 371.73 | 428.47 | 0.00% | `{"200": 40}` |
| `/api/rules` | 40 | 218.59 | 206.91 | 389.55 | 480.24 | 0.00% | `{"200": 40}` |
| `/api/settings` | 40 | 27.19 | 22.08 | 81.85 | 99.69 | 0.00% | `{"200": 40}` |
| `/api/stats` | 40 | 72.27 | 52.46 | 217.08 | 319.44 | 0.00% | `{"200": 40}` |
