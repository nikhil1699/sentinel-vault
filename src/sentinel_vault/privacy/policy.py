"""Tenant data-handling policy for structured fields.

Allowlist model: a field not named in the policy gets ``default_action``, which defaults
to ``drop``. Field *names* are untrusted too: a name that isn't a plain snake_case
identifier is dropped, so PHI can't ride in as a key (``{"John Smith 123-45-6789": 1}``).
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

FIELD_NAME_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")
FieldName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


class FieldAction(StrEnum):
    ALLOW = "allow"        # not sensitive for this tenant; kept as is
    TOKENIZE = "tokenize"  # whole value replaced by a reversible token
    SCAN = "scan"          # free text: detect PII inside and tokenize only that
    DROP = "drop"          # never stored in the tokenized view, never embedded


class DataPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    fields: dict[FieldName, FieldAction] = Field(default_factory=dict, max_length=500)
    default_action: FieldAction = FieldAction.DROP

    def action_for(self, name: str) -> FieldAction:
        if not FIELD_NAME_RE.fullmatch(name):
            return FieldAction.DROP
        return self.fields.get(name, self.default_action)
