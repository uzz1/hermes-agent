from contextvars import Context

import pytest

from deskpilot_hermes.provenance import (
    DeskPilotProvenance,
    copied_context_call,
    provenance,
    require_provenance,
)


def test_missing_provenance_is_denied():
    with pytest.raises(PermissionError, match="provenance missing"):
        require_provenance()


def test_nested_provenance_resets_to_outer_value():
    outer = DeskPilotProvenance("ui", None, "trace-outer")
    inner = DeskPilotProvenance("telegram", "telegram:42", "trace-inner")

    with provenance(outer):
        assert require_provenance() == outer
        with provenance(inner):
            assert require_provenance() == inner
        assert require_provenance() == outer

    with pytest.raises(PermissionError):
        require_provenance()


def test_copied_context_call_preserves_current_provenance():
    value = DeskPilotProvenance("signal", "signal:+27820000000", "trace-1")
    with provenance(value):
        assert copied_context_call(require_provenance) == value

    assert Context().run(lambda: copied_context_call(lambda: "isolated")) == "isolated"
