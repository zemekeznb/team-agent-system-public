"""Environment-configured HTTP entry point for the local F2 A2A experiment."""

from __future__ import annotations

import os
import argparse
from urllib.parse import urlparse

from fastapi import FastAPI

from tas.adapters.a2a.remote_agent import create_remote_agent_app


PUBLIC_URL = "TAS_A2A_PUBLIC_URL"


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
    return create_remote_agent_app(public_url=public_url)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--public-url", required=True)
    args = parser.parse_args()
    import uvicorn

    uvicorn.run(
        create_remote_agent_app(public_url=args.public_url),
        host=args.host,
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
