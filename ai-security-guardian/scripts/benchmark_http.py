#!/usr/bin/env python3
"""HTTP/API benchmark runner for AI-Security-Guardian.

This script intentionally stays lightweight: it uses the already-declared
``requests`` dependency and the Python standard library, rather than bringing
in a load-testing framework such as Locust or k6. It is meant for repeatable
API latency smoke/performance gates; use k6/Locust later when you need
distributed load, browser-grade scenarios, or richer arrival-rate models.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin

try:
    import requests
except ImportError as exc:  # pragma: no cover - requirements include requests.
    raise SystemExit("requests is required; install project requirements.txt") from exc

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENDPOINTS: Tuple[str, ...] = (
    "/api/alerts?limit=100",
    "/api/stats",
    "/api/alerts/types",
    "/api/metrics/traffic?range=24h",
    "/api/metrics/attack_types",
    "/api/metrics/top_attackers",
    "/api/rules",
    "/api/settings",
    "/api/health",
    "/readyz",
)
AUTH_REQUIRED_PREFIXES: Tuple[str, ...] = (
    "/api/alerts",
    "/api/stats",
    "/api/metrics",
    "/api/rules",
    "/api/settings",
)
API_P95_TARGET_MS = 300.0
DETECTION_P95_TARGET_MS = 100.0


@dataclass(frozen=True)
class Endpoint:
    name: str
    path: str
    auth_required: bool


@dataclass
class Sample:
    endpoint: str
    method: str
    status_code: Optional[int]
    latency_ms: float
    ok: bool
    error: str = ""


def _load_dotenv(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _env_value(name: str, dotenv: Dict[str, str], default: str = "") -> str:
    return os.environ.get(name) or dotenv.get(name) or default


def _is_auth_required(path: str) -> bool:
    if path.startswith("/api/health") or path.startswith("/api/auth/"):
        return False
    return any(path.startswith(prefix) for prefix in AUTH_REQUIRED_PREFIXES)


def _parse_endpoints(raw: str) -> List[Endpoint]:
    paths = [item.strip() for item in raw.split(",") if item.strip()]
    endpoints: List[Endpoint] = []
    for path in paths:
        if not path.startswith("/"):
            path = "/" + path
        name = path.split("?", 1)[0]
        endpoints.append(
            Endpoint(name=name, path=path, auth_required=_is_auth_required(path))
        )
    return endpoints


def _percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(round(pct * (len(ordered) - 1)))))
    return ordered[idx]


def _stats(samples: Sequence[Sample]) -> Dict[str, Any]:
    latencies = [s.latency_ms for s in samples]
    status_counts = Counter(str(s.status_code) if s.status_code is not None else "error" for s in samples)
    errors = [s for s in samples if not s.ok]
    total = len(samples)
    return {
        "requests": total,
        "successful_requests": total - len(errors),
        "failed_requests": len(errors),
        "error_rate": (len(errors) / total) if total else 0.0,
        "avg_ms": statistics.fmean(latencies) if latencies else 0.0,
        "p50_ms": _percentile(latencies, 0.50),
        "p95_ms": _percentile(latencies, 0.95),
        "p99_ms": _percentile(latencies, 0.99),
        "min_ms": min(latencies) if latencies else 0.0,
        "max_ms": max(latencies) if latencies else 0.0,
        "status_codes": dict(sorted(status_counts.items())),
        "errors_by_type": dict(sorted(Counter(s.error or "http_error" for s in errors).items())),
    }


def _summarize(samples: Sequence[Sample]) -> Dict[str, Any]:
    by_endpoint: Dict[str, Dict[str, Any]] = {}
    names = sorted({s.endpoint for s in samples})
    for name in names:
        by_endpoint[name] = _stats([s for s in samples if s.endpoint == name])
    return {
        "overall": _stats(samples),
        "endpoints": by_endpoint,
    }


def _url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def login_for_token(
    *,
    base_url: str,
    username: str,
    password: str,
    timeout: float,
) -> str:
    if not username or not password:
        raise RuntimeError(
            "auth is required but username/password are missing; set "
            "BENCHMARK_USERNAME/BENCHMARK_PASSWORD or pass --username/--password"
        )
    resp = requests.post(
        _url(base_url, "/api/auth/login"),
        json={"username": username, "password": password},
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"login failed with HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    token = str(data.get("access_token") or "")
    if not token:
        raise RuntimeError("login response did not contain access_token")
    return token


def bench_detection_latency(iterations: int) -> Dict[str, Any]:
    if iterations <= 0:
        return {"enabled": False}

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

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
    latencies: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        det.detect(feat)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    p95 = _percentile(latencies, 0.95)
    return {
        "enabled": True,
        "iterations": iterations,
        "avg_ms": statistics.fmean(latencies) if latencies else 0.0,
        "p50_ms": _percentile(latencies, 0.50),
        "p95_ms": p95,
        "p99_ms": _percentile(latencies, 0.99),
        "target_p95_ms": DETECTION_P95_TARGET_MS,
        "pass": p95 < DETECTION_P95_TARGET_MS,
    }


def _request_once(
    *,
    session: requests.Session,
    base_url: str,
    endpoint: Endpoint,
    token: str,
    timeout: float,
    ok_statuses: Sequence[int],
) -> Sample:
    headers = {"Accept": "application/json"}
    if endpoint.auth_required and token:
        headers["Authorization"] = f"Bearer {token}"

    started = time.perf_counter()
    try:
        resp = session.get(_url(base_url, endpoint.path), headers=headers, timeout=timeout)
        elapsed = (time.perf_counter() - started) * 1000.0
        ok = resp.status_code in ok_statuses
        return Sample(
            endpoint=endpoint.name,
            method="GET",
            status_code=resp.status_code,
            latency_ms=elapsed,
            ok=ok,
            error="" if ok else f"http_{resp.status_code}",
        )
    except requests.RequestException as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        return Sample(
            endpoint=endpoint.name,
            method="GET",
            status_code=None,
            latency_ms=elapsed,
            ok=False,
            error=type(exc).__name__,
        )


def run_warmup(
    *,
    base_url: str,
    endpoints: Sequence[Endpoint],
    token: str,
    requests_count: int,
    seconds: float,
    workers: int,
    timeout: float,
    ok_statuses: Sequence[int],
) -> None:
    if requests_count <= 0 and seconds <= 0:
        return
    end_at = time.monotonic() + seconds if seconds > 0 else None
    submitted = max(0, requests_count)

    def worker(index: int) -> None:
        session = requests.Session()
        local_count = 0
        while True:
            if end_at is not None and time.monotonic() >= end_at:
                break
            if end_at is None and local_count >= max(1, submitted // workers):
                break
            endpoint = endpoints[(index + local_count) % len(endpoints)]
            _request_once(
                session=session,
                base_url=base_url,
                endpoint=endpoint,
                token=token,
                timeout=timeout,
                ok_statuses=ok_statuses,
            )
            local_count += 1

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, i) for i in range(workers)]
        for future in as_completed(futures):
            future.result()


def run_fixed_requests(
    *,
    base_url: str,
    endpoints: Sequence[Endpoint],
    token: str,
    requests_count: int,
    workers: int,
    timeout: float,
    ok_statuses: Sequence[int],
) -> List[Sample]:
    work = [endpoints[i % len(endpoints)] for i in range(requests_count)]
    random.shuffle(work)
    samples: List[Sample] = []

    def one(endpoint: Endpoint) -> Sample:
        thread_local = _thread_local()
        return _request_once(
            session=thread_local.session,
            base_url=base_url,
            endpoint=endpoint,
            token=token,
            timeout=timeout,
            ok_statuses=ok_statuses,
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(one, endpoint) for endpoint in work]
        for future in as_completed(futures):
            samples.append(future.result())
    return samples


_TLS = threading.local()


def _thread_local() -> Any:
    if not hasattr(_TLS, "session"):
        _TLS.session = requests.Session()
    return _TLS


def run_duration(
    *,
    base_url: str,
    endpoints: Sequence[Endpoint],
    token: str,
    duration: float,
    workers: int,
    timeout: float,
    ok_statuses: Sequence[int],
) -> List[Sample]:
    end_at = time.monotonic() + duration
    samples: List[Sample] = []
    lock = threading.Lock()
    counter = 0

    def worker(worker_id: int) -> List[Sample]:
        nonlocal counter
        session = requests.Session()
        local_samples: List[Sample] = []
        while time.monotonic() < end_at:
            with lock:
                endpoint = endpoints[counter % len(endpoints)]
                counter += 1
            local_samples.append(
                _request_once(
                    session=session,
                    base_url=base_url,
                    endpoint=endpoint,
                    token=token,
                    timeout=timeout,
                    ok_statuses=ok_statuses,
                )
            )
        return local_samples

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, i) for i in range(workers)]
        for future in as_completed(futures):
            samples.extend(future.result())
    return samples


def _format_ms(value: float) -> str:
    return f"{value:.2f}"


def _judgement(summary: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
    overall_p95 = float(summary["overall"]["p95_ms"])
    endpoint_failures = {
        name: {
            "p95_ms": item["p95_ms"],
            "error_rate": item["error_rate"],
        }
        for name, item in summary["endpoints"].items()
        if float(item["p95_ms"]) >= API_P95_TARGET_MS or float(item["error_rate"]) > 0.0
    }
    api_pass = (
        overall_p95 < API_P95_TARGET_MS
        and float(summary["overall"]["error_rate"]) == 0.0
        and not endpoint_failures
    )
    result = {
        "api_target": f"core API P95 < {API_P95_TARGET_MS:.0f}ms",
        "api_pass": api_pass,
        "api_p95_ms": overall_p95,
        "api_endpoint_failures": endpoint_failures,
        "detection_target": f"detection segment P95 < {DETECTION_P95_TARGET_MS:.0f}ms",
        "detection_pass": detection.get("pass") if detection.get("enabled") else None,
        "detection_p95_ms": detection.get("p95_ms"),
    }
    return result


def write_reports(report: Dict[str, Any], output_dir: Path, prefix: str) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = output_dir / f"{prefix}-{stamp}.json"
    md_path = output_dir / f"{prefix}-{stamp}.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def render_markdown(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    overall = summary["overall"]
    judgement = report["judgement"]
    lines = [
        "# AI-Security-Guardian HTTP Benchmark",
        "",
        f"- started_at: `{report['started_at']}`",
        f"- base_url: `{report['base_url']}`",
        f"- mode: `{report['mode']}`",
        f"- workers: `{report['workers']}`",
        f"- elapsed_sec: `{report['elapsed_sec']:.3f}`",
        f"- throughput_rps: `{report['throughput_rps']:.2f}`",
        "",
        "## Judgement",
        "",
        f"- Core API target: `{judgement['api_target']}` -> **{'PASS' if judgement['api_pass'] else 'FAIL'}**",
        f"- Detection target: `{judgement['detection_target']}` -> **{_pass_label(judgement['detection_pass'])}**",
    ]
    if judgement.get("api_endpoint_failures"):
        lines.append(
            f"- Endpoint failures: `{json.dumps(judgement['api_endpoint_failures'], ensure_ascii=False)}`"
        )
    lines.extend(
        [
            "",
            "## Overall",
            "",
            "| requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |",
            "|---:|---:|---:|---:|---:|---:|---|",
            (
                f"| {overall['requests']} | {_format_ms(overall['avg_ms'])} | "
                f"{_format_ms(overall['p50_ms'])} | {_format_ms(overall['p95_ms'])} | "
                f"{_format_ms(overall['p99_ms'])} | {overall['error_rate']:.2%} | "
                f"`{json.dumps(overall['status_codes'], ensure_ascii=False)}` |"
            ),
            "",
            "## Endpoints",
            "",
            "| endpoint | requests | avg ms | P50 ms | P95 ms | P99 ms | error rate | status codes |",
            "|---|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for name, item in summary["endpoints"].items():
        lines.append(
            f"| `{name}` | {item['requests']} | {_format_ms(item['avg_ms'])} | "
            f"{_format_ms(item['p50_ms'])} | {_format_ms(item['p95_ms'])} | "
            f"{_format_ms(item['p99_ms'])} | {item['error_rate']:.2%} | "
            f"`{json.dumps(item['status_codes'], ensure_ascii=False)}` |"
        )

    detection = report.get("detection", {})
    if detection.get("enabled"):
        lines.extend(
            [
                "",
                "## Detection Segment",
                "",
                "| iterations | avg ms | P50 ms | P95 ms | P99 ms | target |",
                "|---:|---:|---:|---:|---:|---|",
                (
                    f"| {detection['iterations']} | {_format_ms(detection['avg_ms'])} | "
                    f"{_format_ms(detection['p50_ms'])} | {_format_ms(detection['p95_ms'])} | "
                    f"{_format_ms(detection['p99_ms'])} | P95 < {detection['target_p95_ms']:.0f}ms |"
                ),
            ]
        )
    lines.append("")
    return "\n".join(lines)


def _pass_label(value: Optional[bool]) -> str:
    if value is None:
        return "SKIP"
    return "PASS" if value else "FAIL"


def _parse_ok_statuses(raw: str) -> Tuple[int, ...]:
    statuses: List[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        statuses.append(int(item))
    return tuple(statuses or [200])


def main(argv: Optional[Sequence[str]] = None) -> int:
    dotenv = _load_dotenv(ROOT / ".env")
    ap = argparse.ArgumentParser(
        description="Production-like HTTP/API benchmark for AI-Security-Guardian"
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("BENCHMARK_API_URL", "http://127.0.0.1:5000"),
        help="Base URL of the Web/API service",
    )
    ap.add_argument(
        "--endpoints",
        default=",".join(DEFAULT_ENDPOINTS),
        help="Comma-separated GET paths to benchmark",
    )
    ap.add_argument("--requests", type=int, default=200, help="Total measured requests")
    ap.add_argument("--workers", type=int, default=8, help="Concurrent worker threads")
    ap.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Measured duration in seconds; when >0 it overrides --requests",
    )
    ap.add_argument("--warmup-requests", type=int, default=20)
    ap.add_argument("--warmup-seconds", type=float, default=0.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument(
        "--username",
        default=_env_value("BENCHMARK_USERNAME", dotenv, _env_value("ADMIN_USERNAME", dotenv, "admin")),
    )
    ap.add_argument(
        "--password",
        default=_env_value("BENCHMARK_PASSWORD", dotenv, _env_value("ADMIN_PASSWORD", dotenv, "")),
    )
    ap.add_argument(
        "--jwt-token",
        default=os.environ.get("BENCHMARK_JWT", ""),
        help="Optional pre-issued token; auto login is used when omitted",
    )
    ap.add_argument("--no-auth", action="store_true", help="Skip login and omit Authorization")
    ap.add_argument("--ok-statuses", default="200", help="Comma-separated HTTP statuses treated as success")
    ap.add_argument("--detect-iters", type=int, default=400)
    ap.add_argument(
        "--output-dir",
        default=str(ROOT / "reports" / "benchmarks"),
        help="Directory for JSON and Markdown reports",
    )
    ap.add_argument("--report-prefix", default="http-benchmark")
    args = ap.parse_args(argv)

    endpoints = _parse_endpoints(args.endpoints)
    if not endpoints:
        raise SystemExit("at least one endpoint is required")
    workers = max(1, args.workers)
    ok_statuses = _parse_ok_statuses(args.ok_statuses)

    token = args.jwt_token.strip()
    needs_auth = any(e.auth_required for e in endpoints)
    if needs_auth and not token and not args.no_auth:
        token = login_for_token(
            base_url=args.base_url,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
        )

    run_warmup(
        base_url=args.base_url,
        endpoints=endpoints,
        token=token,
        requests_count=args.warmup_requests,
        seconds=args.warmup_seconds,
        workers=workers,
        timeout=args.timeout,
        ok_statuses=ok_statuses,
    )

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.perf_counter()
    if args.duration and args.duration > 0:
        samples = run_duration(
            base_url=args.base_url,
            endpoints=endpoints,
            token=token,
            duration=args.duration,
            workers=workers,
            timeout=args.timeout,
            ok_statuses=ok_statuses,
        )
        mode = f"duration:{args.duration:.3f}s"
    else:
        samples = run_fixed_requests(
            base_url=args.base_url,
            endpoints=endpoints,
            token=token,
            requests_count=max(1, args.requests),
            workers=workers,
            timeout=args.timeout,
            ok_statuses=ok_statuses,
        )
        mode = f"requests:{max(1, args.requests)}"
    elapsed = time.perf_counter() - t0

    summary = _summarize(samples)
    detection = bench_detection_latency(args.detect_iters)
    report: Dict[str, Any] = {
        "tool": "scripts/benchmark_http.py",
        "started_at": started_at,
        "base_url": args.base_url,
        "mode": mode,
        "workers": workers,
        "warmup": {
            "requests": args.warmup_requests,
            "seconds": args.warmup_seconds,
        },
        "elapsed_sec": elapsed,
        "throughput_rps": (len(samples) / elapsed) if elapsed > 0 else 0.0,
        "ok_statuses": list(ok_statuses),
        "auth": {
            "login_attempted": bool(needs_auth and not args.jwt_token and not args.no_auth),
            "authorization_header_used": bool(token),
        },
        "targets": {
            "core_api_p95_ms": API_P95_TARGET_MS,
            "detection_p95_ms": DETECTION_P95_TARGET_MS,
        },
        "summary": summary,
        "detection": detection,
    }
    report["judgement"] = _judgement(summary, detection)
    json_path, md_path = write_reports(report, Path(args.output_dir), args.report_prefix)

    overall = summary["overall"]
    print(
        "HTTP overall: "
        f"requests={overall['requests']} avg={overall['avg_ms']:.2f}ms "
        f"p50={overall['p50_ms']:.2f}ms p95={overall['p95_ms']:.2f}ms "
        f"p99={overall['p99_ms']:.2f}ms error_rate={overall['error_rate']:.2%} "
        f"status={overall['status_codes']}"
    )
    if detection.get("enabled"):
        print(
            "Detection segment: "
            f"p95={detection['p95_ms']:.3f}ms "
            f"target<{DETECTION_P95_TARGET_MS:.0f}ms "
            f"{'PASS' if detection['pass'] else 'FAIL'}"
        )
    print(
        "Production target: "
        f"core_api_p95<{API_P95_TARGET_MS:.0f}ms "
        f"{'PASS' if report['judgement']['api_pass'] else 'FAIL'}"
    )
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    return 0 if report["judgement"]["api_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
