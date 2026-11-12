from __future__ import annotations

import copy
import json
import pickle

import pytest
from pydantic import BaseModel

from sentinel_vault.security.sensitive import MASK, Sensitive

SECRET = "123-45-6789"


class Patient(BaseModel):
    mrn: str
    ssn: Sensitive[str]


def test_every_text_path_is_masked() -> None:
    s = Sensitive(SECRET)
    rendered = [repr(s), str(s), f"{s}", f"{s:>20}", "%s" % s,  # noqa: UP031
                "{}".format(s), repr([s])]  # noqa: UP032
    for out in rendered:
        assert SECRET not in out
    assert str(s) == MASK


def test_reveal_is_the_only_way_out() -> None:
    assert Sensitive(SECRET).reveal() == SECRET


def test_pickle_refused() -> None:
    with pytest.raises(TypeError):
        pickle.dumps(Sensitive(SECRET))


def test_deepcopy_keeps_value_and_mask() -> None:
    c = copy.deepcopy(Sensitive(SECRET))
    assert c.reveal() == SECRET
    assert str(c) == MASK


def test_equality_and_unhashable() -> None:
    assert Sensitive("a") == Sensitive("a")
    assert Sensitive(b"a") == Sensitive(b"a")
    assert Sensitive("a") != Sensitive("b")
    assert Sensitive(1) == Sensitive(1)
    assert (Sensitive("a") == "a") is False
    with pytest.raises(TypeError):
        hash(Sensitive("a"))


def test_pydantic_validates_wraps_and_masks_on_dump() -> None:
    p = Patient(mrn="00A-1", ssn=SECRET)  # type: ignore[arg-type]
    assert isinstance(p.ssn, Sensitive)
    assert p.ssn.reveal() == SECRET
    assert SECRET not in repr(p)
    assert SECRET not in p.model_dump_json()
    assert p.model_dump()["ssn"] == MASK
    assert json.loads(p.model_dump_json())["ssn"] == MASK


def test_pydantic_accepts_existing_wrapper() -> None:
    p = Patient(mrn="x", ssn=Sensitive(SECRET))
    assert p.ssn.reveal() == SECRET


def test_pydantic_still_validates_inner_type() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Patient(mrn="x", ssn=12345)  # type: ignore[arg-type]
