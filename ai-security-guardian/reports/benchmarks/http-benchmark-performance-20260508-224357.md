# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T14:43:28+00:00`
- base_url: `http://127.0.0.1:5000`
- mode: `requests:200`
- workers: `8`
- target_rps: `8.0`
- elapsed_sec: `24.893`
- throughput_rps: `8.03`

## Judgement

- Core API target: `core API P95 < 300ms` -> **PASS**
- Detection target: `detection segment P95 < 100ms` -> **PASS**
- HTTP 429 present: `no`
- HTTP 5xx present: `no`

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 200 | 15.32 | 9.32 | 38.70 | 87.49 | 0.00% | `{"200": 200}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/alerts` | 20 | 14.85 | 9.77 | 35.84 | 54.52 | 0.00% | `{"200": 20}` |
| `/api/alerts/types` | 20 | 10.31 | 7.10 | 18.59 | 54.78 | 0.00% | `{"200": 20}` |
| `/api/health` | 20 | 25.02 | 13.79 | 25.45 | 217.69 | 0.00% | `{"200": 20}` |
| `/api/metrics/attack_types` | 20 | 9.60 | 7.48 | 20.14 | 30.09 | 0.00% | `{"200": 20}` |
| `/api/metrics/top_attackers` | 20 | 13.71 | 9.09 | 33.33 | 37.52 | 0.00% | `{"200": 20}` |
| `/api/metrics/traffic` | 20 | 14.11 | 7.54 | 38.70 | 58.82 | 0.00% | `{"200": 20}` |
| `/api/rules` | 20 | 19.36 | 8.62 | 87.49 | 109.89 | 0.00% | `{"200": 20}` |
| `/api/settings` | 20 | 7.94 | 5.80 | 27.33 | 28.37 | 0.00% | `{"200": 20}` |
| `/api/stats` | 20 | 19.62 | 11.13 | 42.03 | 75.02 | 0.00% | `{"200": 20}` |
| `/readyz` | 20 | 18.64 | 13.38 | 39.63 | 72.44 | 0.00% | `{"200": 20}` |

## Detection Segment

| iterations | avg ms | P50 ms | P95 ms | P99 ms | target |
|---:|---:|---:|---:|---:|---|
| 400 | 0.01 | 0.00 | 0.01 | 0.02 | P95 < 100ms |
