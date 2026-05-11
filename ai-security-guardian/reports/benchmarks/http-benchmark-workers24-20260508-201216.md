# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T12:12:10+00:00`
- base_url: `http://127.0.0.1:5000`
- mode: `requests:1000`
- workers: `24`
- elapsed_sec: `3.253`
- throughput_rps: `307.44`

## Judgement

- Core API target: `core API P95 < 300ms` -> **FAIL**
- Detection target: `detection segment P95 < 100ms` -> **PASS**
- Endpoint failures: `{"/api/health": {"p95_ms": 314.33239998295903, "error_rate": 0.0}, "/readyz": {"p95_ms": 392.6430999999866, "error_rate": 0.0}}`

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 1000 | 77.03 | 23.83 | 336.35 | 385.55 | 0.00% | `{"200": 1000}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/alerts` | 100 | 26.52 | 23.84 | 45.14 | 82.03 | 0.00% | `{"200": 100}` |
| `/api/alerts/types` | 100 | 22.52 | 19.27 | 36.01 | 43.83 | 0.00% | `{"200": 100}` |
| `/api/health` | 100 | 255.91 | 265.60 | 314.33 | 339.84 | 0.00% | `{"200": 100}` |
| `/api/metrics/attack_types` | 100 | 22.91 | 20.40 | 38.45 | 54.88 | 0.00% | `{"200": 100}` |
| `/api/metrics/top_attackers` | 100 | 23.60 | 19.80 | 47.01 | 85.32 | 0.00% | `{"200": 100}` |
| `/api/metrics/traffic` | 100 | 23.18 | 19.89 | 44.84 | 86.33 | 0.00% | `{"200": 100}` |
| `/api/rules` | 100 | 20.34 | 19.18 | 32.27 | 46.50 | 0.00% | `{"200": 100}` |
| `/api/settings` | 100 | 12.79 | 11.08 | 22.12 | 33.78 | 0.00% | `{"200": 100}` |
| `/api/stats` | 100 | 42.76 | 41.56 | 66.67 | 79.66 | 0.00% | `{"200": 100}` |
| `/readyz` | 100 | 319.78 | 335.53 | 392.64 | 403.70 | 0.00% | `{"200": 100}` |

## Detection Segment

| iterations | avg ms | P50 ms | P95 ms | P99 ms | target |
|---:|---:|---:|---:|---:|---|
| 400 | 0.01 | 0.01 | 0.01 | 0.01 | P95 < 100ms |
