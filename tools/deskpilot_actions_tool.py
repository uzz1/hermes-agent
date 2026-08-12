"""Closed model-visible DeskPilot action surface.

The handlers in this module are deliberately non-executable. DeskPilot mode
routes model tool calls through ``model_tools.handle_function_call`` and the
public policy wrapper before the typed dispatcher can reach any adapter.
"""

import copy
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
                    f"Authorized DeskPilot action {action_id}@{action_version}."
                ),
                "parameters": copy.deepcopy(spec.inputSchema),
            },
            "handler": _require_public_policy_wrapper,
            "check_fn": _deskpilot_mode_enabled,
        })
    return registrations


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
_FIRST_REGISTRATION, *_REMAINING_REGISTRATIONS = _REGISTRATIONS
registry.register(**_FIRST_REGISTRATION)
for _registration in _REMAINING_REGISTRATIONS:
    registry.register(**_registration)
