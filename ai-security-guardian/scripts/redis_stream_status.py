#!/usr/bin/env python3
"""Print Redis Stream backlog status without requiring redis-cli."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Redis Stream backlog status")
    parser.add_argument("--host", default=os.environ.get("REDIS_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("REDIS_PORT", "6379")))
    parser.add_argument("--db", type=int, default=int(os.environ.get("REDIS_DB", "0")))
    parser.add_argument("--password", default=os.environ.get("REDIS_PASSWORD", ""))
    parser.add_argument("--stream", default=os.environ.get("GUARDIAN_ALERT_STREAM", "guardian:alerts"))
    parser.add_argument("--group", default=os.environ.get("GUARDIAN_ALERT_STREAM_GROUP", "guardian:web"))
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args()


def _main() -> int:
    args = _parse_args()

    from src.utils.redis_client import RedisClient

    client = RedisClient(
        host=args.host,
        port=args.port,
        db=args.db,
        password=args.password,
    )
    payload: Dict[str, Any] = {
        "redis": {
            "host": args.host,
            "port": args.port,
            "db": args.db,
            "mode": client.mode,
            "available": client.is_available,
        },
        "stream": args.stream,
        "group": args.group,
        "xlen": 0,
        "xpending": 0,
        "xinfo_groups": [],
    }

    if client.is_available:
        payload["xlen"] = client.stream_len(args.stream)
        payload["xpending"] = client.stream_pending(args.stream, args.group)
        payload["xinfo_groups"] = client.stream_info_groups(args.stream)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(
            f"Redis {args.host}:{args.port} db={args.db} "
            f"mode={payload['redis']['mode']} available={payload['redis']['available']}"
        )
        print(f"Stream: {args.stream}")
        print(f"XLEN: {payload['xlen']}")
        print(f"XPENDING {args.group}: {payload['xpending']}")
        print("XINFO GROUPS:")
        groups = payload["xinfo_groups"]
        if not groups:
            print("  (none)")
        for group in groups:
            name = group.get("name")
            consumers = group.get("consumers", 0)
            pending = group.get("pending", 0)
            lag = group.get("lag", 0)
            last_id = group.get("last-delivered-id", "")
            print(
                f"  name={name} consumers={consumers} "
                f"pending={pending} lag={lag} last-delivered-id={last_id}"
            )

    if not client.is_available:
        print("ERROR: Redis unavailable or authentication failed.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
