# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T12:11:29+00:00`
- base_url: `http://127.0.0.1:5000`
- mode: `requests:1000`
- workers: `16`
- elapsed_sec: `3.312`
- throughput_rps: `301.90`

## Judgement

- Core API target: `core API P95 < 300ms` -> **PASS**
- Detection target: `detection segment P95 < 100ms` -> **PASS**

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 1000 | 52.55 | 22.56 | 188.70 | 229.64 | 0.00% | `{"200": 1000}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/alerts` | 100 | 25.16 | 23.44 | 38.91 | 50.40 | 0.00% | `{"200": 100}` |
| `/api/alerts/types` | 100 | 20.26 | 18.40 | 33.44 | 44.14 | 0.00% | `{"200": 100}` |
| `/api/health` | 100 | 161.11 | 162.25 | 199.90 | 234.73 | 0.00% | `{"200": 100}` |
| `/api/metrics/attack_types` | 100 | 20.98 | 18.39 | 36.88 | 45.46 | 0.00% | `{"200": 100}` |
| `/api/metrics/top_attackers` | 100 | 23.16 | 20.90 | 42.18 | 85.14 | 0.00% | `{"200": 100}` |
| `/api/metrics/traffic` | 100 | 21.18 | 17.99 | 37.98 | 52.75 | 0.00% | `{"200": 100}` |
| `/api/rules` | 100 | 18.82 | 17.72 | 29.86 | 33.04 | 0.00% | `{"200": 100}` |
| `/api/settings` | 100 | 11.31 | 9.88 | 19.24 | 28.30 | 0.00% | `{"200": 100}` |
| `/api/stats` | 100 | 39.39 | 36.90 | 62.18 | 91.06 | 0.00% | `{"200": 100}` |
| `/readyz` | 100 | 184.16 | 183.78 | 248.68 | 254.12 | 0.00% | `{"200": 100}` |

## Detection Segment

| iterations | avg ms | P50 ms | P95 ms | P99 ms | target |
|---:|---:|---:|---:|---:|---|
| 400 | 0.01 | 0.01 | 0.01 | 0.01 | P95 < 100ms |
