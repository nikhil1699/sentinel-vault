"""Resource-based key policy: the customer's control over what we may do with their CMK.

Semantics (a strict subset of AWS KMS key policies):
- Default deny. An explicit ``Deny`` beats any ``Allow``.
- Principals are exact names. No wildcards: ``*`` is rejected at parse time.
- Conditions on the encryption context: exact-match values and required keys.

Management operations (CreateKey, PutKeyPolicy, RotateKey, ...) are reserved for the
account admin and are not grantable here, so a customer can't lock themselves out
or hand key administration to us by mistake.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

PrincipalName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,62}$")]
CtxKey = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
CtxValue = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")]


class CryptoAction(StrEnum):
    GENERATE_DATA_KEY = "GenerateDataKey"
    DECRYPT = "Decrypt"
    RE_ENCRYPT = "ReEncrypt"


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    encryption_context_equals: dict[CtxKey, CtxValue] = Field(default_factory=dict,
                                                              max_length=10)
    encryption_context_keys: list[CtxKey] = Field(default_factory=list, max_length=10)

    def matches(self, ctx: Mapping[str, str]) -> bool:
        return (all(ctx.get(k) == v for k, v in self.encryption_context_equals.items())
                and all(k in ctx for k in self.encryption_context_keys))


class Statement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sid: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    effect: Literal["Allow", "Deny"]
    principals: list[PrincipalName] = Field(min_length=1, max_length=10)
    actions: list[CryptoAction] = Field(min_length=1)
    condition: Condition = Field(default_factory=Condition)

    def applies(self, principal: str, action: CryptoAction, ctx: Mapping[str, str]) -> bool:
        return principal in self.principals and action in self.actions \
            and self.condition.matches(ctx)


class KeyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["2026-01"] = "2026-01"
    statements: list[Statement] = Field(default_factory=list, max_length=20)


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str  # "allow:<sid>" | "deny:<sid>" | "implicit_deny"


def evaluate(policy: KeyPolicy, principal: str, action: CryptoAction,
             ctx: Mapping[str, str]) -> Decision:
    allow: Statement | None = None
    for st in policy.statements:
        if st.applies(principal, action, ctx):
            if st.effect == "Deny":
                return Decision(False, f"deny:{st.sid}")
            allow = allow or st
    if allow is not None:
        return Decision(True, f"allow:{allow.sid}")
    return Decision(False, "implicit_deny")
