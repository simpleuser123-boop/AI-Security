#!/usr/bin/env python3
"""
基础压测与 P95 采集（与交付文档 §4.2 性能验收对齐）。

在项目根目录执行::

    python scripts/benchmark_p95.py
    python scripts/benchmark_p95.py --api-url http://127.0.0.1:5000 --jwt-token YOUR_TOKEN

指标说明
--------
1. **端到端检测延迟 P95 < 100ms**  
   本脚本对 ``WebAttackDetector.detect`` 包裹 ``perf_counter``，循环 N 次取 P95。  
   反映「特征已构造完成 → 规则/模型推理结束」的进程内耗时。  
   完整链路（抓包 → 聚合 → 特征）需在目标机用 Guardian + 指标 ``guardian_detection_latency_ms``（见 ``/metrics``）另行观测。

2. **Web API P95 < 300ms**  
   对 ``GET /api/alerts``（需 JWT）或回退 ``GET /healthz`` 发起并发 HTTP 请求，打印 P95。  
   默认 ``127.0.0.1:5000`` 需本地已启动 ``python -m web.app``。

3. **Redis Stream 无持续堆积**  
   脚本不强制依赖在线 Redis；若本机无 ``redis-cli``，使用
   ``python scripts/redis_stream_status.py`` 采集 ``XLEN`` / ``XPENDING`` /
   ``XINFO GROUPS``。持续堆积应对：连续采样，正常负载下长度应稳定
   bounded（``MAXLEN`` 软上限），PEL 不持续增长。

无法在单机完成的项（无网卡权限、无 Redis、未启动 Web）请在 ``docs/deployment.md`` 的前置条件中标注，并使用替代验证。
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _p95(latencies_ms: List[float]) -> float:
    if not latencies_ms:
        return 0.0
    s = sorted(latencies_ms)
    idx = max(0, int(round(0.95 * (len(s) - 1))))
    return s[idx]


def bench_detection_latency(iterations: int = 500) -> float:
    from src.detectors.web_detector import WebAttackDetector  # noqa: PLC0415
    from src.features.web_features import WebFeatureExtractor  # noqa: PLC0415

    det = WebAttackDetector()
    ex = WebFeatureExtractor()
    raw = {
        "url": "/api/items?id=1",
        "http_method": "GET",
        "status_code": 200,
        "response_size": 100,
        "src_ip": "198.51.100.1",
    }
    feat = ex.extract(raw)
    lat: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        det.detect(feat)
        lat.append((time.perf_counter() - t0) * 1000.0)
    return _p95(lat)


def bench_http_p95(
    url: str,
    headers: Optional[dict],
    workers: int,
    requests: int,
) -> float:
    try:
        import urllib.request
    except ImportError:
        return 0.0

    latencies: List[float] = []

    def one() -> float:
        t0 = time.perf_counter()
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        return (time.perf_counter() - t0) * 1000.0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one) for _ in range(requests)]
        for f in as_completed(futs):
            latencies.append(f.result())
    return _p95(latencies)


def main() -> int:
    ap = argparse.ArgumentParser(description="P95 基准与 Redis 观测说明")
    ap.add_argument(
        "--api-url",
        default=os.environ.get("BENCHMARK_API_URL", "http://127.0.0.1:5000"),
        help="用于 HTTP 压测的基础 URL",
    )
    ap.add_argument("--jwt-token", default=os.environ.get("BENCHMARK_JWT", ""))
    ap.add_argument("--requests", type=int, default=80)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--detect-iters", type=int, default=400)
    args = ap.parse_args()

    det_p95 = bench_detection_latency(args.detect_iters)
    print(f"[检测链路·进程内] WebAttackDetector P95 ≈ {det_p95:.3f} ms (iters={args.detect_iters})")
    print(f"  目标: P95 < 100 ms（仅规则/推理段；不含采集/网络栈）")

    hdr = {}
    path = "/healthz"
    if args.jwt_token.strip():
        hdr["Authorization"] = f"Bearer {args.jwt_token.strip()}"
        path = "/api/alerts"
    url = args.api_url.rstrip("/") + path
    try:
        http_p95 = bench_http_p95(url, hdr or None, args.workers, args.requests)
        print(f"[HTTP] {path} P95 ≈ {http_p95:.3f} ms (requests={args.requests})")
        print("  目标: P95 < 300 ms（未达标时请检查 DB/Redis/主机负载）")
    except Exception as exc:  # noqa: BLE001
        print(f"[HTTP] 跳过（服务未启动或无权限）: {exc}")
        print("  替代: 启动 Web 后设置 BENCHMARK_JWT 再运行；或仅用 healthz 匿名探测")

    print()
    print("[Redis Stream 堆积观测]")
    print("  redis-cli -a \"$REDIS_PASSWORD\" XLEN guardian:alerts")
    print("  redis-cli -a \"$REDIS_PASSWORD\" XPENDING guardian:alerts guardian:web")
    print("  redis-cli -a \"$REDIS_PASSWORD\" XINFO GROUPS guardian:alerts")
    print("  python scripts/redis_stream_status.py --json")
    print("  正常流量下 XLEN 稳定 bounded；PEL 不持续增长；consumer 持续 ack。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
