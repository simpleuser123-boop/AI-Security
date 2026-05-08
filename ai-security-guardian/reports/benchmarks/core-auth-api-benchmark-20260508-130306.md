# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T05:03:04+00:00`
- base_url: `http://127.0.0.1:5097`
- mode: `requests:200`
- workers: `8`
- elapsed_sec: `1.241`
- throughput_rps: `161.17`

## Judgement

- Core API target: `core API P95 < 300ms` -> **PASS**
- Detection target: `detection segment P95 < 100ms` -> **SKIP**

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 200 | 48.85 | 48.98 | 73.77 | 98.42 | 0.00% | `{"200": 200}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/alerts/types` | 40 | 49.67 | 46.97 | 88.41 | 98.42 | 0.00% | `{"200": 40}` |
| `/api/metrics/traffic` | 40 | 45.01 | 49.27 | 59.08 | 77.11 | 0.00% | `{"200": 40}` |
| `/api/rules` | 40 | 50.55 | 51.04 | 66.12 | 87.25 | 0.00% | `{"200": 40}` |
| `/api/settings` | 40 | 48.69 | 48.05 | 70.51 | 106.03 | 0.00% | `{"200": 40}` |
| `/api/stats` | 40 | 50.33 | 49.98 | 67.38 | 108.70 | 0.00% | `{"200": 40}` |
