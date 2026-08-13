import copy
import builtins
import importlib
from unittest.mock import MagicMock

import pytest

import model_tools
from deskpilot.actions import ActionRegistry, POSTCONDITIONS, PRECONDITIONS
from deskpilot_hermes.integration import TOOL_ACTIONS
from deskpilot_hermes.tool_dispatcher import _packaged_actions_path
from tools.deskpilot_actions_tool import _model_facing_schema
from tools.registry import (
    ToolRegistry,
    discover_builtin_tools,
    invalidate_check_fn_cache,
    registry,
)
from toolsets import resolve_toolset, validate_toolset
from hermes_cli import tools_config


DESKPILOT_NAMES = set(TOOL_ACTIONS)
FORBIDDEN_NAMES = {
    "terminal",
    "computer_use",
    "send_message",
    "browser",
    "tool_search",
    "tool_describe",
    "tool_call",
}


def _parent_specs():
    parent = ActionRegistry.from_yaml(
        _packaged_actions_path(), PRECONDITIONS, POSTCONDITIONS
    )
    return dict(parent._specs)


def _reset_definition_caches():
    model_tools._clear_tool_defs_cache()
    invalidate_check_fn_cache()


def _definitions(*, skip_tool_search_assembly=False):
    _reset_definition_caches()
    return model_tools.get_tool_definitions(
        enabled_toolsets=["deskpilot"],
        quiet_mode=True,
        skip_tool_search_assembly=skip_tool_search_assembly,
    )


def _functions(definitions):
    return {
        definition["function"]["name"]: definition["function"]
        for definition in definitions
    }


def _replace_registry_entry(entry, schema):
    registry.register(
        name=entry.name,
        toolset=entry.toolset,
        schema=schema,
        handler=entry.handler,
        check_fn=entry.check_fn,
        requires_env=entry.requires_env,
        is_async=entry.is_async,
        description=entry.description,
        emoji=entry.emoji,
        max_result_size_chars=entry.max_result_size_chars,
        dynamic_schema_overrides=entry.dynamic_schema_overrides,
    )


def test_builtin_discovery_registers_exact_closed_deskpilot_surface(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    imported = discover_builtin_tools()

    assert "tools.deskpilot_actions_tool" in imported
    assert validate_toolset("deskpilot") is True
    assert set(resolve_toolset("deskpilot")) == DESKPILOT_NAMES
    assert set(registry.get_tool_names_for_toolset("deskpilot")) == DESKPILOT_NAMES


def test_deskpilot_definitions_are_hidden_without_mode(monkeypatch):
    monkeypatch.delenv("DESKPILOT_MODE", raising=False)

    assert _definitions(skip_tool_search_assembly=True) == []


def test_visible_definitions_copy_parent_schemas_and_identify_actions(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    specs = _parent_specs()

    functions = _functions(_definitions(skip_tool_search_assembly=True))

    assert set(functions) == DESKPILOT_NAMES
    assert set(functions).isdisjoint(FORBIDDEN_NAMES)
    for tool_name, (action_id, action_version) in TOOL_ACTIONS.items():
        function = functions[tool_name]
        assert function["description"] == (
            f"Execute authorized DeskPilot action {action_id}@{action_version}."
        )
        # The model is shown a narrowed copy, not the enforcement schema: enum
        # crashes the pinned model's chat template. ActionRegistry keeps the
        # original and remains the gate — see test_model_schema.py.
        assert function["parameters"] == _model_facing_schema(
            specs[(action_id, action_version)].inputSchema
        )
        assert (
            function["parameters"] is not specs[(action_id, action_version)].inputSchema
        )


def test_registry_entries_are_closed_stubs(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    discover_builtin_tools()

    handlers = set()
    for tool_name in DESKPILOT_NAMES:
        entry = registry.get_entry(tool_name)
        assert entry is not None
        assert entry.toolset == "deskpilot"
        assert entry.check_fn() is True
        handlers.add(entry.handler)
        with pytest.raises(
            PermissionError, match="^DeskPilot tools require the public policy wrapper$"
        ):
            entry.handler({})
        assert entry.handler.__closure__ is None
    assert len(handlers) == 1


def test_atomic_registration_rejects_parent_action_mismatch():
    module = importlib.import_module("tools.deskpilot_actions_tool")
    isolated = ToolRegistry()
    mismatched = _parent_specs()
    mismatched.pop(next(iter(mismatched)))

    with pytest.raises(RuntimeError, match="DeskPilot action registry mismatch"):
        module._register_deskpilot_tools(isolated, mismatched)

    assert isolated.get_all_tool_names() == []


def test_tool_search_cannot_collapse_or_add_bridges(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        "tools.tool_search.load_config",
        lambda: type(
            "Config",
            (),
            {
                "enabled": "on",
                "threshold_pct": 0.0,
                "min_tools": 1,
                "always_available": frozenset(),
            },
        )(),
    )

    functions = _functions(_definitions())

    assert set(functions) == DESKPILOT_NAMES
    assert set(functions).isdisjoint({"tool_search", "tool_describe", "tool_call"})


@pytest.mark.parametrize("invalid_first", [True, False])
def test_exact_deskpilot_surface_cache_does_not_bypass_duplicate_rejection(
    monkeypatch, invalid_first
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        "tools.tool_search.load_config",
        lambda: type(
            "Config",
            (),
            {
                "enabled": "on",
                "threshold_pct": 0.0,
                "min_tools": 1,
                "always_available": frozenset(),
            },
        )(),
    )
    _reset_definition_caches()

    exact_toolsets = tools_config._get_platform_tools(
        {"platform_toolsets": {"cli": ["deskpilot", "no_mcp"]}},
        "cli",
    )
    selections = [["deskpilot", "deskpilot"], exact_toolsets]
    if not invalid_first:
        selections.reverse()
    exact_names = None
    for enabled_toolsets in selections:
        if type(enabled_toolsets) is list:
            with pytest.raises(RuntimeError):
                model_tools.get_tool_definitions(
                    enabled_toolsets=enabled_toolsets,
                    quiet_mode=True,
                )
        else:
            definitions = model_tools.get_tool_definitions(
                enabled_toolsets=enabled_toolsets,
                quiet_mode=True,
            )
            exact_names = set(_functions(definitions))

    assert exact_names == DESKPILOT_NAMES


@pytest.mark.parametrize("selection_kind", ["literal_list", "platform_set"])
def test_closed_deskpilot_surface_precedes_kanban_worker_expansion(
    monkeypatch, selection_kind
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_deskpilot")
    monkeypatch.setattr(
        "tools.tool_search.load_config",
        lambda: type(
            "Config",
            (),
            {
                "enabled": "on",
                "threshold_pct": 0.0,
                "min_tools": 1,
                "always_available": frozenset(),
            },
        )(),
    )
    if selection_kind == "literal_list":
        enabled_toolsets = ["deskpilot"]
    else:
        enabled_toolsets = tools_config._get_platform_tools(
            {"platform_toolsets": {"cli": ["deskpilot", "no_mcp"]}},
            "cli",
        )
    _reset_definition_caches()

    names = set(
        _functions(
            model_tools.get_tool_definitions(
                enabled_toolsets=enabled_toolsets,
                quiet_mode=True,
            )
        )
    )

    assert names == DESKPILOT_NAMES
    assert not any(name.startswith("kanban_") for name in names)
    assert names.isdisjoint({"tool_search", "tool_describe", "tool_call"})


def test_ordinary_kanban_worker_still_expands_restricted_toolsets(monkeypatch):
    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_ordinary")
    _reset_definition_caches()

    names = set(
        _functions(
            model_tools.get_tool_definitions(
                enabled_toolsets=["terminal"],
                quiet_mode=True,
                skip_tool_search_assembly=True,
            )
        )
    )

    assert {"kanban_show", "kanban_complete", "kanban_block"}.issubset(names)


def test_globally_registered_browseros_mcp_stays_out(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    name = "mcp_browseros_private_test"
    registry.register(
        name=name,
        toolset="mcp-browseros",
        schema={
            "name": name,
            "description": "must stay hidden",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=lambda *_args, **_kwargs: "{}",
    )
    try:
        assert name not in _functions(_definitions(skip_tool_search_assembly=True))
    finally:
        registry.deregister(name)
        _reset_definition_caches()


def test_mode_flip_does_not_leave_stale_visibility(monkeypatch):
    _reset_definition_caches()
    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    assert (
        model_tools.get_tool_definitions(
            enabled_toolsets=["deskpilot"],
            quiet_mode=True,
            skip_tool_search_assembly=True,
        )
        == []
    )

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    visible = model_tools.get_tool_definitions(
        enabled_toolsets=["deskpilot"],
        quiet_mode=True,
        skip_tool_search_assembly=True,
    )
    assert set(_functions(visible)) == DESKPILOT_NAMES

    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    assert (
        model_tools.get_tool_definitions(
            enabled_toolsets=["deskpilot"],
            quiet_mode=True,
            skip_tool_search_assembly=True,
        )
        == []
    )


def test_registered_parameters_are_detached_from_parent_and_mapping(monkeypatch):
    module = importlib.import_module("tools.deskpilot_actions_tool")
    specs = _parent_specs()
    isolated = ToolRegistry()
    original = copy.deepcopy(specs)

    module._register_deskpilot_tools(isolated, specs)
    first_name, first_action = next(iter(TOOL_ACTIONS.items()))
    specs[first_action].inputSchema["mutated_after_registration"] = True

    entry = isolated.get_entry(first_name)
    assert entry.schema["parameters"] == _model_facing_schema(
        original[first_action].inputSchema
    )
    assert "mutated_after_registration" not in entry.schema["parameters"]


@pytest.mark.parametrize("platform", ["acp", "cli", "cron", "telegram", "signal"])
def test_deskpilot_platforms_resolve_only_closed_toolset_before_expansion(
    monkeypatch, platform
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        tools_config,
        "_get_plugin_toolset_keys",
        lambda: pytest.fail("plugin expansion was touched"),
    )
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "toolsets":
            pytest.fail("toolset import was touched")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    config = {"platform_toolsets": {platform: ["deskpilot", "no_mcp"]}}

    assert tools_config._get_platform_tools(config, platform) == {"deskpilot"}


@pytest.mark.parametrize("platform", ["acp", "cli", "cron", "telegram", "signal"])
@pytest.mark.parametrize(
    ("configured", "include_platform_key"),
    [
        (None, False),
        (None, True),
        ("deskpilot,no_mcp", True),
        (("deskpilot", "no_mcp"), True),
        ([], True),
        (["no_mcp", "deskpilot"], True),
        (["deskpilot", "no_mcp", "web"], True),
        (["deskpilot"], True),
    ],
)
def test_deskpilot_platform_config_fails_before_any_expansion(
    monkeypatch, platform, configured, include_platform_key
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        tools_config,
        "_get_plugin_toolset_keys",
        lambda: pytest.fail("plugin expansion was touched"),
    )
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "toolsets":
            pytest.fail("toolset import was touched")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    config = {}
    if include_platform_key:
        config = {"platform_toolsets": {platform: configured}}

    with pytest.raises(
        RuntimeError,
        match=rf"^DeskPilot {platform} requires \[deskpilot,no_mcp\]$",
    ):
        tools_config._get_platform_tools(config, platform)


def test_deskpilot_mode_does_not_change_other_platform_resolution(monkeypatch):
    config = {"platform_toolsets": {"discord": ["web", "no_mcp"]}}
    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    ordinary = tools_config._get_platform_tools(config, "discord")

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    assert tools_config._get_platform_tools(config, "discord") == ordinary
    assert "web" in ordinary


@pytest.mark.parametrize(
    ("enabled_toolsets", "disabled_toolsets"),
    [
        (None, None),
        (["hermes-acp"], None),
        (["deskpilot", "terminal"], None),
        (["deskpilot", "mcp-browseros"], None),
        (["deskpilot", "deskpilot"], None),
        ((name for name in ["deskpilot"]), None),
        ("deskpilot", None),
        (["deskpilot"], ["terminal"]),
    ],
)
@pytest.mark.parametrize(
    "definition_fn_name", ["get_tool_definitions", "_compute_tool_definitions"]
)
def test_central_model_boundary_rejects_nonexact_deskpilot_selection_before_expansion(
    monkeypatch, enabled_toolsets, disabled_toolsets, definition_fn_name
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        model_tools.registry,
        "get_definitions",
        lambda *_args, **_kwargs: pytest.fail("registry assembly was touched"),
    )
    monkeypatch.setattr(
        "toolsets.get_all_toolsets",
        lambda: pytest.fail("default toolset expansion was touched"),
    )
    monkeypatch.setattr(
        model_tools,
        "validate_toolset",
        lambda _name: pytest.fail("toolset validation was touched"),
    )
    definition_fn = getattr(model_tools, definition_fn_name)

    with pytest.raises(
        RuntimeError,
        match=r"^DeskPilot tool definitions require exactly \[deskpilot\] and no disabled toolsets$",
    ):
        definition_fn(
            enabled_toolsets=enabled_toolsets,
            disabled_toolsets=disabled_toolsets,
            quiet_mode=True,
        )


@pytest.mark.parametrize(
    "enabled_toolsets",
    [["deskpilot"], ("deskpilot",), {"deskpilot"}],
)
@pytest.mark.parametrize("disabled_toolsets", [None, [], (), set()])
def test_central_model_boundary_accepts_supported_exact_selection_only(
    monkeypatch, enabled_toolsets, disabled_toolsets
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_closed")
    _reset_definition_caches()

    names = set(
        _functions(
            model_tools.get_tool_definitions(
                enabled_toolsets=enabled_toolsets,
                disabled_toolsets=disabled_toolsets,
                quiet_mode=True,
            )
        )
    )

    assert names == DESKPILOT_NAMES
    assert names.isdisjoint({
        "memory",
        "todo",
        "delegate_task",
        "tool_search",
        "tool_describe",
        "tool_call",
    })
    assert not any(name.startswith("kanban_") for name in names)


@pytest.mark.parametrize(
    "definition_fn_name", ["get_tool_definitions", "_compute_tool_definitions"]
)
def test_central_model_boundary_rejects_nonempty_falsey_disabled_container(
    monkeypatch, definition_fn_name
):
    class FalseyDisabled(list):
        def __bool__(self):
            return False

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    definition_fn = getattr(model_tools, definition_fn_name)

    with pytest.raises(RuntimeError):
        definition_fn(
            enabled_toolsets=["deskpilot"],
            disabled_toolsets=FalseyDisabled(["terminal"]),
            quiet_mode=True,
        )


def test_ordinary_mode_keeps_default_and_nonexact_behavior(monkeypatch):
    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    _reset_definition_caches()

    assert isinstance(
        model_tools.get_tool_definitions(quiet_mode=True),
        list,
    )
    assert isinstance(
        model_tools.get_tool_definitions(
            enabled_toolsets=["terminal", "file"],
            quiet_mode=True,
            skip_tool_search_assembly=True,
        ),
        list,
    )


def test_warm_ordinary_cache_cannot_bypass_deskpilot_rejection(monkeypatch):
    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    _reset_definition_caches()
    model_tools.get_tool_definitions(
        enabled_toolsets=["terminal"],
        quiet_mode=True,
    )

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    with pytest.raises(RuntimeError):
        model_tools.get_tool_definitions(
            enabled_toolsets=["terminal"],
            quiet_mode=True,
        )


@pytest.mark.parametrize("registry_drift", ["extra", "missing", "duplicate"])
def test_central_model_boundary_rejects_deskpilot_definition_drift(
    monkeypatch, registry_drift
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    _reset_definition_caches()
    extra_name = "unexpected_deskpilot_tool"

    if registry_drift == "extra":
        registry.register(
            name=extra_name,
            toolset="deskpilot",
            schema={
                "name": extra_name,
                "description": "must never be exposed",
                "parameters": {"type": "object", "properties": {}},
            },
            handler=lambda *_args, **_kwargs: "{}",
        )
    else:
        original_get_definitions = registry.get_definitions

        def drift_definitions(*args, **kwargs):
            definitions = original_get_definitions(*args, **kwargs)
            if registry_drift == "missing":
                return definitions[1:]
            return [*definitions, definitions[0]]

        monkeypatch.setattr(registry, "get_definitions", drift_definitions)

    try:
        with pytest.raises(
            RuntimeError,
            match="^DeskPilot tool definitions do not match authorized actions$",
        ):
            model_tools.get_tool_definitions(
                enabled_toolsets=["deskpilot"],
                quiet_mode=True,
            )
    finally:
        if registry_drift == "extra":
            registry.deregister(extra_name)
        _reset_definition_caches()


@pytest.mark.parametrize(
    "tampering",
    [
        "parameters",
        "scalar_type",
        "container_type",
        "nonfinite_number",
        "description",
        "function_field",
    ],
)
def test_central_model_boundary_rejects_replaced_deskpilot_contract(
    monkeypatch, tampering
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    tool_name = next(iter(TOOL_ACTIONS))
    original = registry.get_entry(tool_name)
    assert original is not None
    altered_schema = copy.deepcopy(original.schema)
    if tampering == "parameters":
        altered_schema["parameters"]["unexpected"] = True
    elif tampering == "scalar_type":
        altered_schema["parameters"]["additionalProperties"] = 0
    elif tampering == "container_type":
        altered_schema["parameters"]["required"] = tuple(
            altered_schema["parameters"]["required"]
        )
    elif tampering == "nonfinite_number":
        altered_schema["parameters"]["unexpected"] = float("nan")
    elif tampering == "description":
        altered_schema["description"] = "Execute an unauthorized replacement."
    else:
        altered_schema["unexpected"] = True

    _replace_registry_entry(original, altered_schema)
    _reset_definition_caches()
    try:
        with pytest.raises(
            RuntimeError,
            match="^DeskPilot tool definitions do not match authorized actions$",
        ):
            model_tools.get_tool_definitions(
                enabled_toolsets=["deskpilot"],
                quiet_mode=True,
            )
    finally:
        _replace_registry_entry(original, original.schema)
        _reset_definition_caches()


def test_central_model_boundary_rejects_unexpected_top_level_definition_field(
    monkeypatch,
):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    _reset_definition_caches()
    original_get_definitions = registry.get_definitions

    def add_top_level_field(*args, **kwargs):
        definitions = original_get_definitions(*args, **kwargs)
        definitions[0]["unexpected"] = True
        return definitions

    monkeypatch.setattr(registry, "get_definitions", add_top_level_field)

    with pytest.raises(
        RuntimeError,
        match="^DeskPilot tool definitions do not match authorized actions$",
    ):
        model_tools.get_tool_definitions(
            enabled_toolsets=["deskpilot"],
            quiet_mode=True,
        )


def test_expected_deskpilot_definition_contract_returns_deep_copies():
    module = importlib.import_module("tools.deskpilot_actions_tool")

    first = module.get_expected_deskpilot_definitions()
    tool_name = next(iter(first))
    first[tool_name]["function"]["parameters"]["poisoned"] = True

    second = module.get_expected_deskpilot_definitions()

    assert "poisoned" not in second[tool_name]["function"]["parameters"]


def test_deskpilot_definition_cache_is_detached_and_revalidated(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    _reset_definition_caches()

    first = model_tools.get_tool_definitions(
        enabled_toolsets=["deskpilot"],
        quiet_mode=True,
    )
    first[0]["function"]["name"] = "terminal"
    first[0]["function"]["parameters"]["poisoned"] = True

    second = model_tools.get_tool_definitions(
        enabled_toolsets=["deskpilot"],
        quiet_mode=True,
    )
    names = set(_functions(second))

    assert names == DESKPILOT_NAMES
    assert "terminal" not in names
    assert all(
        "poisoned" not in definition["function"]["parameters"] for definition in second
    )


def test_deskpilot_definition_cache_rejects_deep_contract_corruption(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    _reset_definition_caches()
    model_tools.get_tool_definitions(
        enabled_toolsets=["deskpilot"],
        quiet_mode=True,
    )
    cached = next(iter(model_tools._tool_defs_cache.values()))
    cached[0]["function"]["description"] = "Corrupted cached description."

    try:
        with pytest.raises(
            RuntimeError,
            match="^DeskPilot tool definitions do not match authorized actions$",
        ):
            model_tools.get_tool_definitions(
                enabled_toolsets=["deskpilot"],
                quiet_mode=True,
            )
    finally:
        _reset_definition_caches()


def test_fresh_deskpilot_definitions_are_detached_when_sanitizer_fails(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        "tools.schema_sanitizer.sanitize_tool_schemas",
        lambda _definitions: (_ for _ in ()).throw(RuntimeError("sanitizer failed")),
    )
    _reset_definition_caches()
    tool_name = next(iter(TOOL_ACTIONS))
    entry = registry.get_entry(tool_name)
    assert entry is not None
    original_parameters = copy.deepcopy(entry.schema["parameters"])

    try:
        definitions = model_tools.get_tool_definitions(
            enabled_toolsets=["deskpilot"],
            quiet_mode=False,
        )
        functions = _functions(definitions)
        functions[tool_name]["parameters"]["poisoned"] = True

        assert entry.schema["parameters"] == original_parameters
    finally:
        entry.schema["parameters"] = original_parameters
        _reset_definition_caches()


def test_actual_acp_agent_selection_is_closed_before_model_boundary(monkeypatch):
    from acp_adapter import session as acp_session

    captured = {}

    class CapturingAgent:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr("run_agent.AIAgent", CapturingAgent)
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {"platform_toolsets": {"acp": ["deskpilot", "no_mcp"]}},
    )
    monkeypatch.setattr(
        "hermes_cli.runtime_provider.resolve_runtime_provider", lambda **_kwargs: {}
    )
    monkeypatch.setattr(acp_session, "_register_task_cwd", lambda *_args: None)
    manager = acp_session.SessionManager(db=MagicMock())

    manager._make_agent(session_id="acp-session", cwd="/tmp")

    assert captured["enabled_toolsets"] == ["deskpilot"]
    definitions = model_tools.get_tool_definitions(
        enabled_toolsets=captured["enabled_toolsets"],
        quiet_mode=True,
    )
    assert {item["function"]["name"] for item in definitions} == DESKPILOT_NAMES


def test_actual_cron_fallback_and_per_job_override_fail_closed(monkeypatch):
    from cron.scheduler import _resolve_cron_enabled_toolsets

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    missing_config = _resolve_cron_enabled_toolsets({}, {})
    per_job_override = _resolve_cron_enabled_toolsets(
        {"enabled_toolsets": ["terminal"]}, {}
    )

    assert missing_config is None
    assert per_job_override == ["terminal"]
    for enabled_toolsets in (missing_config, per_job_override):
        with pytest.raises(RuntimeError):
            model_tools.get_tool_definitions(
                enabled_toolsets=enabled_toolsets,
                quiet_mode=True,
            )


def test_oneshot_native_selection_fails_closed_at_model_boundary(monkeypatch):
    from hermes_cli.oneshot import _normalize_toolsets

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    enabled_toolsets = _normalize_toolsets("terminal,file")

    assert enabled_toolsets == ["terminal", "file"]
    with pytest.raises(RuntimeError):
        model_tools.get_tool_definitions(
            enabled_toolsets=enabled_toolsets,
            quiet_mode=True,
        )
