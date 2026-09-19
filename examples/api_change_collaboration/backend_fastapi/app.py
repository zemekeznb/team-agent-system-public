"""Minimal FastAPI backend for the F2 API-change collaboration scenario."""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Annotated

from fastapi import FastAPI, HTTPException, Path
from pydantic import BaseModel, ConfigDict


CONTRACT_ENVIRONMENT_VARIABLE = "TAS_EXAMPLE_USER_CONTRACT"


class UserContractVersion(StrEnum):
    V1 = "v1"
    V2 = "v2"


# F2-062 will change this tracked default in a real commit after the v1 client exists.
DEFAULT_USER_CONTRACT = UserContractVersion.V1


class UserResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    userId: str
    userName: str


class UserResponseV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    userId: str
    name: str


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    contractVersion: UserContractVersion


_USERS = {"user-001": "Ada Lovelace"}
UserId = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")]


def _contract_version(value: UserContractVersion | str | None) -> UserContractVersion:
    configured = os.environ.get(CONTRACT_ENVIRONMENT_VARIABLE, DEFAULT_USER_CONTRACT.value) if value is None else value
    try:
        return UserContractVersion(configured)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"{CONTRACT_ENVIRONMENT_VARIABLE} must be 'v1' or 'v2'") from error


def create_app(contract_version: UserContractVersion | str | None = None) -> FastAPI:
    """Create one process with one unambiguous response contract."""

    selected = _contract_version(contract_version)
    application = FastAPI(
        title="TAS API Change Collaboration Example",
        version=selected.value,
        description="Controlled F2 fixture; not a production TAS API.",
    )

    @application.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", contractVersion=selected)

    if selected is UserContractVersion.V1:

        @application.get("/api/users/{user_id}", response_model=UserResponseV1)
        def get_user_v1(user_id: UserId) -> UserResponseV1:
            name = _user_name(user_id)
            return UserResponseV1(userId=user_id, userName=name)

    else:

        @application.get("/api/users/{user_id}", response_model=UserResponseV2)
        def get_user_v2(user_id: UserId) -> UserResponseV2:
            name = _user_name(user_id)
            return UserResponseV2(userId=user_id, name=name)

    return application


def _user_name(user_id: str) -> str:
    try:
        return _USERS[user_id]
    except KeyError as error:
        raise HTTPException(status_code=404, detail="user_not_found") from error


app = create_app()
