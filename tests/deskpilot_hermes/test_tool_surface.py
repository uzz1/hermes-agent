import copy
import builtins
import importlib

import pytest

import model_tools
from deskpilot.actions import ActionRegistry, POSTCONDITIONS, PRECONDITIONS
from deskpilot_hermes.integration import TOOL_ACTIONS
from deskpilot_hermes.tool_dispatcher import _packaged_actions_path
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
            f"Authorized DeskPilot action {action_id}@{action_version}."
        )
        assert function["parameters"] == specs[(action_id, action_version)].inputSchema
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


@pytest.mark.parametrize("duplicate_first", [True, False])
def test_exact_deskpilot_surface_cache_does_not_alias_duplicate_list(
    monkeypatch, duplicate_first
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
    lists = [["deskpilot", "deskpilot"], exact_toolsets]
    if not duplicate_first:
        lists.reverse()
    observed = {}
    for enabled_toolsets in lists:
        definitions = model_tools.get_tool_definitions(
            enabled_toolsets=enabled_toolsets,
            quiet_mode=True,
        )
        observed[type(enabled_toolsets)] = set(_functions(definitions))

    assert observed[set] == DESKPILOT_NAMES
    assert observed[list] == {"tool_search", "tool_describe", "tool_call"}


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
    assert entry.schema["parameters"] == original[first_action].inputSchema
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
