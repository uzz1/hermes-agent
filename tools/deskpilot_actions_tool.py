"""Closed model-visible DeskPilot action surface.

The handlers in this module are deliberately non-executable. DeskPilot mode
routes model tool calls through ``model_tools.handle_function_call`` and the
public policy wrapper before the typed dispatcher can reach any adapter.
"""

import copy
import json
import os
from collections.abc import Mapping
from typing import Any

from deskpilot_hermes.integration import TOOL_ACTIONS
from deskpilot_hermes.tool_dispatcher import load_packaged_action_registry
from tools.registry import ToolRegistry, registry


_POLICY_WRAPPER_ERROR = "DeskPilot tools require the public policy wrapper"


def _deskpilot_mode_enabled() -> bool:
    return os.environ.get("DESKPILOT_MODE") == "1"


_deskpilot_mode_enabled._skip_check_fn_cache = True


def _require_public_policy_wrapper(*_args: Any, **_kwargs: Any) -> None:
    raise PermissionError(_POLICY_WRAPPER_ERROR)


def _packaged_action_specs() -> dict[tuple[str, int], Any]:
    parent_registry = load_packaged_action_registry()
    return dict(parent_registry._specs)


_JSON_TYPES: tuple[tuple[type, str], ...] = (
    (bool, "boolean"),
    (int, "integer"),
    (float, "number"),
    (str, "string"),
)


def _json_type_of(values: list[Any]) -> str:
    """Name the JSON type shared by a set of enum values."""
    kinds = {
        name for value in values for kind, name in _JSON_TYPES if isinstance(value, kind)
    }
    # bool is a subclass of int; prefer the narrower name when every value is one.
    if kinds == {"boolean", "integer"}:
        return "boolean"
    return kinds.pop() if len(kinds) == 1 else "string"


def _model_facing_schema(schema: Any) -> Any:
    """Return a copy of ``schema`` that the pinned model can actually render.

    ``enum`` is removed everywhere and its values are folded into the field's
    description. gemma-4-e4b's chat template raises on ``enum`` — bare, it hits
    an undefined-value filter; typed, it hits an unimplemented Jinja test — and
    because every tool ships in one request, a single occurrence breaks the turn.

    This narrows only what the model is shown. ``ActionRegistry`` keeps the
    original schema and remains the enforcement point, so a model that invents a
    value outside the list is still refused at dispatch.
    """
    if isinstance(schema, list):
        return [_model_facing_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema

    rendered = {
        key: _model_facing_schema(value)
        for key, value in schema.items()
        if key not in ("enum", "const")
    }
    # `const` is `enum` with one member and fails the same way, so both are
    # folded into a description the template can render.
    values = schema.get("enum")
    if not isinstance(values, list) and "const" in schema:
        values = [schema["const"]]
    if isinstance(values, list) and values:
        rendered.setdefault("type", _json_type_of(values))
        permitted = (
            f"Must be: {values[0]}."
            if len(values) == 1
            else "One of: " + ", ".join(str(value) for value in values) + "."
        )
        existing = rendered.get("description")
        rendered["description"] = f"{existing} {permitted}".strip() if existing else permitted
    return rendered


def _prepare_registrations(
    action_specs: Mapping[tuple[str, int], Any],
) -> list[dict[str, Any]]:
    expected_actions = set(TOOL_ACTIONS.values())
    if set(action_specs) != expected_actions:
        raise RuntimeError("DeskPilot action registry mismatch")

    registrations = []
    for tool_name, action_key in TOOL_ACTIONS.items():
        action_id, action_version = action_key
        spec = action_specs[action_key]
        registrations.append({
            "name": tool_name,
            "toolset": "deskpilot",
            "schema": {
                "name": tool_name,
                "description": (
                    f"Execute authorized DeskPilot action {action_id}@{action_version}."
                ),
                "parameters": _model_facing_schema(spec.inputSchema),
            },
            "handler": _require_public_policy_wrapper,
            "check_fn": _deskpilot_mode_enabled,
        })
    return registrations


def _expected_definitions_json(registrations: list[dict[str, Any]]) -> str:
    definitions = {
        registration["name"]: {
            "type": "function",
            "function": copy.deepcopy(registration["schema"]),
        }
        for registration in registrations
    }
    return json.dumps(definitions, sort_keys=True, separators=(",", ":"))


def get_expected_deskpilot_definitions() -> dict[str, dict[str, Any]]:
    """Return a detached copy of the parent-derived model definition contract."""
    return json.loads(_EXPECTED_DEFINITIONS_JSON)


def _register_deskpilot_tools(
    target_registry: ToolRegistry,
    action_specs: Mapping[tuple[str, int], Any] | None = None,
) -> None:
    registrations = _prepare_registrations(
        _packaged_action_specs() if action_specs is None else action_specs
    )
    for registration in registrations:
        target_registry.register(**registration)


# Keep one direct top-level ``registry.register`` call so builtin discovery's
# AST filter recognizes this module. All parent data is loaded and validated
# before the first registration, preserving atomicity on registry mismatch.
_REGISTRATIONS = _prepare_registrations(_packaged_action_specs())
_EXPECTED_DEFINITIONS_JSON = _expected_definitions_json(_REGISTRATIONS)
_FIRST_REGISTRATION, *_REMAINING_REGISTRATIONS = _REGISTRATIONS
registry.register(**_FIRST_REGISTRATION)
for _registration in _REMAINING_REGISTRATIONS:
    registry.register(**_registration)
