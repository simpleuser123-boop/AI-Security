#!/usr/bin/env python3
"""Single-enterprise private Beta E2E drill.

The drill is intentionally conservative:
- it never prints secret values;
- it exercises response execution only while DRY_RUN is true;
- it writes a uniquely tagged drill alert/action/audit trail so results can be
  queried and cleaned up by operators later.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional
from urllib.parse import urljoin

import requests
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass
class DrillStep:
    no: int
    name: str
    status: str
    detail: str
    data: Dict[str, Any] = field(default_factory=dict)


class DrillFailure(RuntimeError):
    pass


class ApiSession:
    def __init__(self, *, base_url: str = "", flask_client: Any = None) -> None:
        self.base_url = base_url.rstrip("/") + "/" if base_url else ""
        self.flask_client = flask_client
        self.token: Optional[str] = None

    def request(self, method: str, path: str, **kwargs: Any) -> tuple[int, Any, Dict[str, str]]:
        headers = dict(kwargs.pop("headers", {}) or {})
        if self.token:
            headers.setdefault("Authorization", f"Bearer {self.token}")
        if self.flask_client is not None:
            resp = self.flask_client.open(path, method=method, headers=headers, **kwargs)
            try:
                body = resp.get_json()
            except Exception:  # noqa: BLE001
                body = resp.get_data(as_text=True)
            if body is None:
                body = resp.get_data(as_text=True)
            return resp.status_code, body, dict(resp.headers)

        resp = requests.request(
            method,
            urljoin(self.base_url, path.lstrip("/")),
            headers=headers,
            timeout=float(os.environ.get("BETA_DRILL_HTTP_TIMEOUT_SEC", "10")),
            **kwargs,
        )
        content_type = resp.headers.get("content-type", "")
        if "json" in content_type:
            body = resp.json()
        else:
            body = resp.text
        return resp.status_code, body, dict(resp.headers)


def _load_env_file(path: Path) -> int:
    if not path.exists():
        return 0
    loaded = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value
        loaded += 1
    return loaded


def _safe_db_url(value: str) -> str:
    if not value:
        return "(missing)"
    try:
        return make_url(value).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001
        return "(invalid DATABASE_URL)"


def _latest_migration_revision() -> str:
    versions = ROOT / "migrations" / "versions"
    latest = ""
    for path in sorted(versions.glob("*.py")):
        if path.name.startswith("__"):
            continue
        latest = path.stem.split("_", 2)[0] + "_" + path.stem.split("_", 2)[1]
    return latest


def _database_url() -> str:
    value = os.environ.get("DATABASE_URL", "").strip()
    if not value:
        raise DrillFailure("DATABASE_URL is missing")
    return value


def _assert_http(status: int, body: Any, expected: Iterable[int], label: str) -> None:
    if status not in set(expected):
        raise DrillFailure(f"{label} returned HTTP {status}: {_summarize_body(body)}")


def _summarize_body(body: Any) -> str:
    text = json.dumps(body, ensure_ascii=False, sort_keys=True) if not isinstance(body, str) else body
    text = text.replace(os.environ.get("ADMIN_PASSWORD", "\0"), "***")
    return text[:500]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_step(steps: list[DrillStep], no: int, name: str, fn: Callable[[], Dict[str, Any]]) -> None:
    started = time.perf_counter()
    try:
        data = fn()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        detail = str(data.pop("detail", "ok"))
        data["elapsed_ms"] = elapsed_ms
        steps.append(DrillStep(no, name, "PASS", detail, data))
        print(f"[PASS] {no:02d}. {name}: {detail}")
    except DrillFailure as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        steps.append(DrillStep(no, name, "FAIL", str(exc), {"elapsed_ms": elapsed_ms}))
        print(f"[FAIL] {no:02d}. {name}: {exc}")
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        detail = f"{type(exc).__name__}: {_summarize_body(str(exc))}"
        steps.append(
            DrillStep(no, name, "FAIL", detail, {"elapsed_ms": elapsed_ms})
        )
        print(f"[FAIL] {no:02d}. {name}: {detail}")


def _make_inprocess_api() -> ApiSession:
    os.environ.setdefault("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    os.environ.setdefault("AUDIT_INTEGRITY_PATROL", "false")
    from web.app import create_app

    app, _socketio = create_app()
    app.config["TESTING"] = True
    return ApiSession(flask_client=app.test_client())


def _seed_alert(alert_id: str, token: str) -> None:
    from web.app import create_app, push_alert

    app, _socketio = create_app()
    with app.app_context():
        push_alert(
            app,
            {
                "id": alert_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "198.51.100.66",
                "threat_type": "private_beta_drill",
                "level": "high",
                "status": "open",
                "summary": token,
                "details": {"drill": True, "token": token},
            },
        )


def _readiness() -> Dict[str, Any]:
    from scripts.check_production_readiness import _checks

    results = [check() for check in _checks("private-beta")]
    failures = [r for r in results if not r.ok]
    warnings = [r for r in results if r.status == "WARN"]
    if failures:
        names = ", ".join(r.name for r in failures)
        raise DrillFailure(f"readiness failed: {names}")
    return {
        "detail": f"{len(results)} gate(s) passed; warnings={len(warnings)}",
        "checks": [{"name": r.name, "status": r.status, "reason": r.reason} for r in results],
    }


def _migration_status() -> Dict[str, Any]:
    engine = create_engine(_database_url(), pool_pre_ping=True)
    latest = _latest_migration_revision()
    with engine.begin() as conn:
        inspector = inspect(conn)
        if "alembic_version" not in inspector.get_table_names():
            raise DrillFailure("alembic_version table is missing")
        current = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    if latest and current != latest:
        raise DrillFailure(f"database revision {current!r} != latest {latest!r}")
    return {"detail": f"database revision is current: {current}", "database_url": _safe_db_url(_database_url())}


def _redis_status() -> Dict[str, Any]:
    from src.utils.redis_client import RedisClient

    stream = os.environ.get("GUARDIAN_ALERT_STREAM", "guardian:alerts")
    group = os.environ.get("GUARDIAN_ALERT_STREAM_GROUP", "guardian:web")
    client = RedisClient(
        host=os.environ.get("REDIS_HOST", "127.0.0.1"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        db=int(os.environ.get("REDIS_DB", "0")),
        password=os.environ.get("REDIS_PASSWORD", ""),
    )
    if not client.is_available:
        raise DrillFailure("Redis unavailable or authentication failed")
    client.stream_ensure_group(stream, group)
    return {
        "detail": f"Redis ping ok; stream={stream} xlen={client.stream_len(stream)} xpending={client.stream_pending(stream, group)}",
        "stream": stream,
        "group": group,
        "xinfo_groups": client.stream_info_groups(stream),
    }


def _model_manifest() -> Dict[str, Any]:
    from scripts.bootstrap_models import EXPECTED_ARTIFACTS, SAVED_DIR

    model_dir = Path(os.environ.get("MODEL_DIR") or SAVED_DIR)
    missing: list[str] = []
    manifests: list[str] = []
    for files in EXPECTED_ARTIFACTS.values():
        for name in files:
            path = model_dir / name
            if not path.exists() or path.stat().st_size <= 0:
                missing.append(name)
            if name.endswith(".model_manifest.json") and path.exists():
                json.loads(path.read_text(encoding="utf-8"))
                manifests.append(name)
    if missing:
        raise DrillFailure(f"missing model artifact(s): {', '.join(missing[:5])}")
    return {"detail": f"model artifacts ok; manifests={len(manifests)}", "model_dir": str(model_dir)}


def _login(api: ApiSession, username: str, password: str) -> Dict[str, Any]:
    status, body, _headers = api.request("GET", "/login")
    _assert_http(status, body, {200, 302}, "GET /login")
    if not password:
        raise DrillFailure("admin password is unavailable; set BETA_DRILL_ADMIN_PASSWORD or ADMIN_PASSWORD")
    status, body, _headers = api.request(
        "POST",
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    _assert_http(status, body, {200}, "POST /api/auth/login")
    token = body.get("access_token") if isinstance(body, dict) else None
    if not token:
        raise DrillFailure("login response did not include access_token")
    api.token = token
    role = body.get("role", "unknown") if isinstance(body, dict) else "unknown"
    return {"detail": f"login ok as {username} role={role}"}


def _alert_injection(api: ApiSession, alert_id: str, token: str) -> Dict[str, Any]:
    if not api.token:
        raise DrillFailure("login token is missing; skip alert injection")
    _seed_alert(alert_id, token)
    status, body, headers = api.request("GET", f"/api/alerts?q={token}&limit=20")
    _assert_http(status, body, {200}, "GET /api/alerts")
    if not isinstance(body, list) or not any(item.get("id") == alert_id for item in body):
        raise DrillFailure("injected alert was not queryable")
    return {"detail": f"alert injected and queryable: {alert_id}", "total": headers.get("X-Total-Count")}


def _alert_disposition(api: ApiSession, alert_id: str) -> Dict[str, Any]:
    if not api.token:
        raise DrillFailure("login token is missing; skip alert disposition")
    status, body, _headers = api.request(
        "POST",
        f"/api/alerts/{alert_id}/status",
        json={"status": "investigating", "note": "private beta E2E drill triage"},
    )
    _assert_http(status, body, {200}, "POST /api/alerts/<id>/status")
    if not isinstance(body, dict) or body.get("status") != "investigating":
        raise DrillFailure("alert status did not transition to investigating")
    return {"detail": "alert triage status updated"}


def _notification(api: ApiSession, email: str) -> Dict[str, Any]:
    if not api.token:
        raise DrillFailure("login token is missing; skip notification test")
    status, body, _headers = api.request("POST", "/api/settings/test_email", json={"email": email})
    _assert_http(status, body, {200}, "POST /api/settings/test_email")
    if not isinstance(body, dict) or body.get("ok") is not True:
        raise DrillFailure(f"email notification test failed: {_summarize_body(body)}")
    return {"detail": "notification channel test accepted"}


def _response_flow(api: ApiSession, alert_id: str, target_ip: str) -> Dict[str, Any]:
    if not api.token:
        raise DrillFailure("login token is missing; skip response approval")
    status, body, _headers = api.request(
        "POST",
        "/api/response/actions",
        json={
            "alert_id": alert_id,
            "action_type": "ban_ip",
            "target_type": "ip",
            "target": target_ip,
            "ttl_seconds": 900,
            "reason": "private beta drill confirmed high alert",
            "evidence": {"source": "private_beta_e2e_drill", "alert_id": alert_id},
            "rollback_plan": {"method": "scheduled_unblock_or_manual_rollback"},
        },
    )
    _assert_http(status, body, {202}, "POST /api/response/actions")
    action_id = int(body["response_action_id"])

    status, body, _headers = api.request(
        "POST",
        f"/api/response/actions/{action_id}/approve",
        json={"reason": "private beta drill human approval"},
    )
    _assert_http(status, body, {200}, "POST /api/response/actions/<id>/approve")
    if body.get("status") != "approved":
        raise DrillFailure("approval did not reach approved status")

    status, body, _headers = api.request(
        "POST",
        f"/api/response/actions/{action_id}/execute",
        json={"reason": "private beta DRY_RUN execution validation"},
    )
    _assert_http(status, body, {200}, "POST /api/response/actions/<id>/execute")
    if body.get("status") != "dry_run_simulated" or body.get("provider_called") is not False:
        raise DrillFailure(f"DRY_RUN response was not simulated safely: {_summarize_body(body)}")
    return {"detail": f"approval and DRY_RUN execution ok; action_id={action_id}", "action_id": action_id}


def _audit_query(api: ApiSession, alert_id: str, action_id: int) -> Dict[str, Any]:
    if not api.token:
        raise DrillFailure("login token is missing; skip audit query")
    status, body, _headers = api.request("GET", f"/api/audit/events?resource_id={alert_id}&limit=20")
    _assert_http(status, body, {200}, "GET /api/audit/events alert")
    alert_events = body.get("total", 0) if isinstance(body, dict) else 0
    status, body, _headers = api.request("GET", f"/api/audit/events?resource_id={action_id}&limit=20")
    _assert_http(status, body, {200}, "GET /api/audit/events response")
    response_events = body.get("total", 0) if isinstance(body, dict) else 0
    if alert_events < 1 or response_events < 1:
        raise DrillFailure(f"audit events missing: alert={alert_events} response={response_events}")
    return {"detail": f"audit query ok; alert_events={alert_events} response_events={response_events}"}


def _report_query(api: ApiSession) -> Dict[str, Any]:
    if not api.token:
        raise DrillFailure("login token is missing; skip report query")
    status, body, _headers = api.request("GET", "/api/reports/summary?period=day")
    _assert_http(status, body, {200}, "GET /api/reports/summary")
    if not isinstance(body, dict):
        raise DrillFailure("report summary did not return JSON object")
    return {"detail": "daily report summary query ok", "keys": sorted(body.keys())[:12]}


def _metrics(api: ApiSession) -> Dict[str, Any]:
    status, body, _headers = api.request("GET", "/metrics")
    _assert_http(status, body, {200}, "GET /metrics")
    text_body = body if isinstance(body, str) else json.dumps(body)
    required = [
        "guardian_alerts_total",
        "guardian_model_ready",
        "redis_stream_pending",
        "guardian_response_actions_total",
        "guardian_http_requests_total",
    ]
    missing = [name for name in required if name not in text_body]
    if missing:
        raise DrillFailure(f"/metrics missing series: {', '.join(missing)}")
    return {"detail": f"/metrics contains {len(required)} required series"}


def _backup_restore_sample(backup_dir: Path) -> Dict[str, Any]:
    db_url = make_url(_database_url())
    if db_url.get_backend_name() == "sqlite":
        db_path = Path(db_url.database or "")
        if not db_path.is_absolute():
            db_path = ROOT / db_path
        if not db_path.exists():
            raise DrillFailure(f"SQLite database file not found: {db_path}")
        out_dir = backup_dir / datetime.now().strftime("%Y%m%d%H%M%S")
        out_dir.mkdir(parents=True, exist_ok=True)
        copied = out_dir / db_path.name
        shutil.copy2(db_path, copied)
        digest = _sha256_file(copied)
        restored = out_dir / f"restore-check-{db_path.name}"
        shutil.copy2(copied, restored)
        engine = create_engine(f"sqlite:///{restored.as_posix()}")
        with engine.begin() as conn:
            tables = inspect(conn).get_table_names()
            alert_count = conn.execute(text("SELECT COUNT(*) FROM alerts")).scalar() if "alerts" in tables else 0
        return {
            "detail": f"SQLite backup copy and restore sample ok; alerts={alert_count}",
            "backup_file": str(copied),
            "sha256": digest,
        }

    candidates = [
        p
        for p in backup_dir.glob("**/*")
        if p.is_file() and p.suffix in {".dump", ".sql", ".gz"}
    ]
    if not candidates:
        raise DrillFailure(
            "non-SQLite restore sample requires an existing database dump under "
            f"{backup_dir}; generate templates with "
            "scripts/generate_private_deployment_evidence.py when PostgreSQL is "
            "only reachable in the customer environment"
        )
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    digest = _sha256_file(newest)
    sidecar = newest.with_name(f"{newest.name}.sha256")
    sha256_status = "missing_sidecar"
    if sidecar.exists():
        expected = sidecar.read_text(encoding="utf-8").split()[0].strip()
        if expected != digest:
            raise DrillFailure(f"backup SHA256 mismatch for {newest.name}")
        sha256_status = "verified"
    return {
        "detail": f"backup artifact sampled: {newest.name}; sha256={sha256_status}",
        "artifact": str(newest),
        "sha256": digest,
        "sha256_status": sha256_status,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the private Beta single-enterprise E2E drill.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Passing standard:\n"
            "  - all 14 steps print PASS and the process exits 0;\n"
            "  - no secret values are printed;\n"
            "  - response execution returns dry_run_simulated with provider_called=false;\n"
            "  - JSON evidence, when requested, records only redacted environment context.\n"
        ),
    )
    parser.add_argument("--base-url", default=os.environ.get("BETA_DRILL_BASE_URL", ""), help="optional deployed Web/API base URL; omitted uses in-process Flask test client")
    parser.add_argument("--env-file", default=str(ROOT / ".env"), help="env file to read without overriding existing variables")
    parser.add_argument("--skip-env-file", action="store_true")
    parser.add_argument("--username", default=os.environ.get("BETA_DRILL_ADMIN_USERNAME") or os.environ.get("ADMIN_USERNAME", "admin"))
    parser.add_argument("--password-env", default="BETA_DRILL_ADMIN_PASSWORD", help="environment variable that contains the login password; falls back to ADMIN_PASSWORD")
    parser.add_argument("--notification-email", default=os.environ.get("BETA_DRILL_NOTIFICATION_EMAIL", "beta-drill@example.test"))
    parser.add_argument("--target-ip", default=os.environ.get("BETA_DRILL_TARGET_IP", "198.51.100.77"))
    parser.add_argument("--backup-dir", default=os.environ.get("BETA_DRILL_BACKUP_DIR", str(ROOT / "backups")))
    parser.add_argument("--json-output", default="", help="optional path for a JSON evidence report")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if not args.skip_env_file:
        loaded = _load_env_file(Path(args.env_file))
        print(f"Env file loaded: {Path(args.env_file)} ({loaded} value(s), existing env preserved)")
    else:
        print("Env file loaded: skipped")
    print(f"Database: {_safe_db_url(os.environ.get('DATABASE_URL', ''))}")
    print("Secrets: redacted")

    api_holder: Dict[str, ApiSession] = {}
    password = os.environ.get(args.password_env) or os.environ.get("ADMIN_PASSWORD", "")
    drill_id = uuid.uuid4().hex[:10]
    token = f"private-beta-drill-{drill_id}"
    alert_id = f"drill-{drill_id}"
    steps: list[DrillStep] = []
    response_action_id = {"value": None}

    def api() -> ApiSession:
        if "api" not in api_holder:
            api_holder["api"] = ApiSession(base_url=args.base_url) if args.base_url else _make_inprocess_api()
        return api_holder["api"]

    _run_step(steps, 1, "生产 readiness 检查", _readiness)
    _run_step(steps, 2, "数据库迁移状态检查", _migration_status)
    _run_step(steps, 3, "Redis 连通和 Stream 状态检查", _redis_status)
    _run_step(steps, 4, "模型 manifest 检查", _model_manifest)
    _run_step(steps, 5, "Web/API 登录", lambda: _login(api(), args.username, password))
    _run_step(steps, 6, "告警模拟或注入", lambda: _alert_injection(api(), alert_id, token))
    _run_step(steps, 7, "告警处置", lambda: _alert_disposition(api(), alert_id))
    _run_step(steps, 8, "通知测试", lambda: _notification(api(), args.notification_email))

    def response_wrapper() -> Dict[str, Any]:
        data = _response_flow(api(), alert_id, args.target_ip)
        response_action_id["value"] = data["action_id"]
        return data

    _run_step(steps, 9, "响应审批测试", response_wrapper)
    _run_step(
        steps,
        10,
        "DRY_RUN 响应验证",
        lambda: {"detail": f"DRY_RUN validated by response action {response_action_id['value']}"} if response_action_id["value"] else (_ for _ in ()).throw(DrillFailure("response action was not created")),
    )
    _run_step(
        steps,
        11,
        "审计事件查询",
        lambda: _audit_query(api(), alert_id, int(response_action_id["value"] or 0)),
    )
    _run_step(steps, 12, "报表查询", lambda: _report_query(api()))
    _run_step(steps, 13, "/metrics 指标检查", lambda: _metrics(api()))
    _run_step(steps, 14, "备份和恢复抽检", lambda: _backup_restore_sample(Path(args.backup_dir)))

    failed = [s for s in steps if s.status != "PASS"]
    report = {
        "drill_id": drill_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url or "in-process",
        "database_url": _safe_db_url(os.environ.get("DATABASE_URL", "")),
        "steps": [s.__dict__ for s in steps],
        "passed": len(failed) == 0,
    }
    if args.json_output:
        out = Path(args.json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Evidence JSON: {out}")

    print("-" * 72)
    if failed:
        print(f"Result: FAIL ({len(failed)} failed step(s)); drill_id={drill_id}")
        return 1
    print(f"Result: PASS; drill_id={drill_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
