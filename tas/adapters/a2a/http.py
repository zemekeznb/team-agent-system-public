"""Environment-configured HTTP entry point for the local F2 A2A experiment."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI

from tas.adapters.a2a.remote_agent import create_remote_agent_app
from tas.adapters.a2a.sqlite_task_store import SQLiteA2ATaskStore


PUBLIC_URL = "TAS_A2A_PUBLIC_URL"
TASK_STORE_DATABASE = "TAS_A2A_TASK_STORE_DATABASE"


def create_app() -> FastAPI:
    public_url = os.environ.get(PUBLIC_URL, "")
    parsed = urlparse(public_url)
    if (
        not public_url.strip()
        or parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "TAS_A2A_PUBLIC_URL must be an HTTP(S) URL without credentials"
        )
    raw_task_store = os.environ.get(TASK_STORE_DATABASE)
    task_store = None
    if raw_task_store is not None:
        task_store_path = Path(raw_task_store)
        if not task_store_path.is_absolute():
            raise RuntimeError("TAS_A2A_TASK_STORE_DATABASE must be an absolute path")
        task_store = SQLiteA2ATaskStore(task_store_path)
    return create_remote_agent_app(public_url=public_url, task_store=task_store)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--task-store-database", type=Path)
    args = parser.parse_args()
    import uvicorn

    uvicorn.run(
        create_remote_agent_app(
            public_url=args.public_url,
            task_store=(
                SQLiteA2ATaskStore(args.task_store_database.resolve())
                if args.task_store_database is not None
                else None
            ),
        ),
        host=args.host,
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
