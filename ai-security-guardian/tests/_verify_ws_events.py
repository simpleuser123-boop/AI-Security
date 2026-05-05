"""Phase 7 P2 尾声：验证 WebSocket 事件名已统一为 `alert`。

手测脚本（不纳入 pytest）。依赖正在运行的 Flask 服务 + python-socketio 客户端。
"""
from __future__ import annotations

import sys
import time

import requests
import socketio

BASE = "http://127.0.0.1:5000"


def login() -> str:
    resp = requests.post(
        f"{BASE}/api/auth/login",
        json={"username": "admin", "password": "changeme"},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def main() -> int:
    token = login()
    counters = {"alert": 0, "new_alert": 0, "threat_detected": 0, "alert_updated": 0}

    client = socketio.Client(reconnection=False)

    @client.on("alert")
    def _on_alert(data):  # type: ignore[unused-function]
        counters["alert"] += 1

    @client.on("new_alert")
    def _on_new_alert(data):  # type: ignore[unused-function]
        counters["new_alert"] += 1

    @client.on("threat_detected")
    def _on_td(data):  # type: ignore[unused-function]
        counters["threat_detected"] += 1

    @client.on("alert_updated")
    def _on_updated(data):  # type: ignore[unused-function]
        counters["alert_updated"] += 1

    # 优先 websocket；如果 websocket-client 未装，退回 polling
    try:
        client.connect(BASE, transports=["websocket"])
    except Exception:
        client.connect(BASE, transports=["polling"])
    time.sleep(0.5)

    # 触发 8 条演示告警 → 应产生 8 次 `alert` 事件，0 次其它
    resp = requests.post(
        f"{BASE}/api/alerts/_seed",
        headers={"Authorization": f"Bearer {token}"},
        json={"count": 8},
        timeout=10,
    )
    resp.raise_for_status()
    created = resp.json().get("created", 0)

    # 拿第一条 id 做一次状态变更 → 应产生 1 次 `alert_updated`
    items = requests.get(
        f"{BASE}/api/alerts?limit=1",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    ).json()
    first_id = items[0]["id"] if items else None
    if first_id:
        resp = requests.post(
            f"{BASE}/api/alerts/{first_id}/status",
            headers={"Authorization": f"Bearer {token}"},
            json={"status": "acknowledged"},
            timeout=5,
        )
        resp.raise_for_status()

    # 等事件到齐（SocketIO 是异步派发）
    time.sleep(1.5)
    client.disconnect()

    print(f"seeded: {created} alerts")
    print(f"counters: {counters}")

    ok = (
        counters["alert"] == created
        and counters["new_alert"] == 0
        and counters["threat_detected"] == 0
        and counters["alert_updated"] >= (1 if first_id else 0)
    )
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
