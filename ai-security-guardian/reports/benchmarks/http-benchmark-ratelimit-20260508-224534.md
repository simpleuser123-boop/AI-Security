# AI-Security-Guardian HTTP Benchmark

- started_at: `2026-05-08T14:45:34+00:00`
- base_url: `http://127.0.0.1:5001`
- mode: `requests:6`
- workers: `3`
- target_rps: `0`
- elapsed_sec: `0.043`
- throughput_rps: `139.68`

## Judgement

- Rate-limit target: `HTTP 429 appears under intentionally low limit` -> **PASS**
- Server errors present: `no`

## Overall

| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---:|---:|---:|---:|---:|---:|---|
| 6 | 17.86 | 5.67 | 40.37 | 40.37 | 66.67% | `{"200": 2, "429": 4}` |

## Endpoints

| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |
|---|---:|---:|---:|---:|---:|---:|---|
| `/api/stats` | 6 | 17.86 | 5.67 | 40.37 | 40.37 | 66.67% | `{"200": 2, "429": 4}` |
