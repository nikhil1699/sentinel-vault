"""Mock external LLM (the untrusted system on the far side of the PHI boundary).

It records every request it receives, so tests and the attack runner can prove that
no raw PII crossed the boundary. ``app.state.mode`` changes its behavior:

- ``summarize`` (default): echo the first 200 chars of each user message.
- ``obedient``: echo everything, as if a prompt injection fully succeeded.
- ``error``: fail with 503.
"""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException

from sentinel_vault.security.http import build_app

MAX_RECORDED = 1_000


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user"]
    content: str = Field(max_length=200_000)


class CompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = Field(default="mock-1", max_length=64)
    messages: list[Message] = Field(min_length=1, max_length=64)


class CompletionResponse(BaseModel):
    answer: str


class Received(BaseModel):
    requests: list[CompletionRequest]


def create_app(configure_logs: bool = True) -> FastAPI:
    app = build_app("mock-llm", "Mock LLM (external system)", configure_logs=configure_logs)
    app.state.received = []
    app.state.mode = "summarize"

    @app.post("/v1/complete", response_model=CompletionResponse)
    async def complete(body: CompletionRequest, request: Request) -> CompletionResponse:
        state = request.app.state
        if state.mode == "error":
            raise HTTPException(status_code=503)
        received: list[CompletionRequest] = state.received
        received.append(body)
        del received[:-MAX_RECORDED]
        user = [m.content for m in body.messages if m.role == "user"]
        if state.mode == "obedient":
            return CompletionResponse(answer="\n".join(user))
        return CompletionResponse(answer="Summary: " + " | ".join(u[:200] for u in user))

    @app.get("/v1/received", response_model=Received)
    async def received(request: Request) -> Received:
        return Received(requests=list(request.app.state.received))

    return app
