# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T04:55:13+00:00`
- base_url: `http://127.0.0.1:5097`
- mode: `requests:200`
- workers: `8`
- elapsed_sec: `4.297`
- throughput_rps: `46.55`

## Judgement

- Core API target: `core API P95 < 300ms` -> **FAIL**
- Detection target: `detection segment P95 < 100ms` -> **SKIP**
- Endpoint failures: `{"/api/alerts/types": {"p95_ms": 431.6814999328926, "error_rate": 0.0}, "/api/metrics/traffic": {"p95_ms": 442.4306000582874, "error_rate": 0.0}, "/api/rules": {"p95_ms": 392.04459998290986, "error_rate": 0.0}, "/api/settings": {"p95_ms": 424.3572000414133, "error_rate": 0.0}, "/api/stats": {"p95_ms": 500.6071000825614, "error_rate": 0.0}}`

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 200 | 168.24 | 129.00 | 467.94 | 524.33 | 0.00% | `{"200": 200}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/alerts/types` | 40 | 140.19 | 111.15 | 431.68 | 517.89 | 0.00% | `{"200": 40}` |
| `/api/metrics/traffic` | 40 | 131.85 | 92.56 | 442.43 | 524.33 | 0.00% | `{"200": 40}` |
| `/api/rules` | 40 | 153.45 | 129.00 | 392.04 | 498.45 | 0.00% | `{"200": 40}` |
| `/api/settings` | 40 | 191.81 | 136.53 | 424.36 | 1825.53 | 0.00% | `{"200": 40}` |
| `/api/stats` | 40 | 223.91 | 195.68 | 500.61 | 886.59 | 0.00% | `{"200": 40}` |
