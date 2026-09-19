"""Pydantic arg models for built-in tools (deterministic input validation)."""

from pydantic import BaseModel, ConfigDict


class EchoArgs(BaseModel):
    # Echo accepts arbitrary key/values and returns them.
    model_config = ConfigDict(extra="allow")


class NoArgs(BaseModel):
    # Tools that take no arguments; anything provided is rejected.
    model_config = ConfigDict(extra="forbid")
