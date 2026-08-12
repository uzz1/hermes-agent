import json
from types import SimpleNamespace

import pytest

import deskpilot_hermes.startup as startup


PROBES = {
    "accessibility",
    "zed_running",
    "ghostty_running",
    "browseros_ready",
    "cua_ready",
    "terminal_ready",
    "path_exists",
    "path_user_scoped",
    "source_exists",
    "paths_user_scoped",
    "recipient_exact",
    "local_ui_present",
    "health_probes_ready",
    "trace_store_ready",
}
EXECUTORS = {"hammerspoon", "browseros", "cua", "terminal", "file"}


class ClosedAdapter:
    def execute(self, action_id, inputs):
        return {"observed": True}


class FakeRegistry:
    def __init__(self, entries):
        self.entries = entries
        self.calls = []

    def get_entry(self, name):
        return self.entries.get(name)

    def dispatch(self, name, arguments):
        self.calls.append((name, arguments))
        return self.entries[name].result


def entry(parameters, result, check_fn=lambda: True):
    return SimpleNamespace(
        schema={"parameters": parameters}, result=result, check_fn=check_fn
    )


def test_runtime_call_validates_live_schema_availability_and_result(monkeypatch):
    fake = FakeRegistry({
        "runtime": entry(
            {
                "type": "object",
                "properties": {"value": {"type": "integer"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            json.dumps({"ok": True, "value": 1}),
        )
    })
    monkeypatch.setattr(startup, "registry", fake)

    assert startup._runtime_call("runtime", {"value": 1}) == {
        "ok": True,
        "value": 1,
    }
    with pytest.raises(RuntimeError, match="schema mismatch"):
        startup._runtime_call("runtime", {"value": "1"})
    fake.entries["runtime"].check_fn = lambda: False
    with pytest.raises(RuntimeError, match="unavailable"):
        startup._runtime_call("runtime", {"value": 1})
    fake.entries["runtime"].check_fn = lambda: True
    fake.entries["runtime"].result = json.dumps({"ok": False, "error": "secret"})
    with pytest.raises(RuntimeError, match="reported an error"):
        startup._runtime_call("runtime", {"value": 1})


def test_browser_navigation_requires_exact_observed_url(monkeypatch):
    calls = []

    def runtime(name, arguments):
        calls.append((name, arguments))
        if name == "mcp_browseros_get_active_page":
            return {"page": {"url": "https://example.test/review"}}
        return {"ok": True}

    monkeypatch.setattr(startup, "_runtime_call", runtime)
    adapter = startup.BrowserMessagingAdapter()
    assert adapter.execute("browser.open", {"url": "https://example.test/review"}) == {
        "browser_url_matches": True
    }
    assert calls == [
        (
            "mcp_browseros_navigate_page",
            {"type": "url", "url": "https://example.test/review"},
        ),
        ("mcp_browseros_get_active_page", {}),
    ]

    monkeypatch.setattr(
        startup,
        "_runtime_call",
        lambda name, _args: (
            {"url": "https://example.test/review-attacker"}
            if name == "mcp_browseros_get_active_page"
            else {"ok": True}
        ),
    )
    with pytest.raises(RuntimeError, match="URL unverified"):
        adapter.execute("browser.open", {"url": "https://example.test/review"})


def test_install_runtime_constructs_one_closed_dispatcher(monkeypatch):
    monkeypatch.setattr(startup, "_installed_dispatcher", None)
    monkeypatch.setattr(startup, "set_tool_dispatcher", lambda value: value)
    captured = []

    class Dispatcher:
        def __init__(self, policy, adapters, environment, approval):
            captured.append((policy, adapters, environment, approval))

    monkeypatch.setattr(startup, "DeskPilotToolDispatcher", Dispatcher)
    environment = {name: lambda _inputs: True for name in PROBES}
    adapters = {name: ClosedAdapter() for name in EXECUTORS}

    first = startup.install_deskpilot_runtime(environment, adapters)
    second = startup.install_deskpilot_runtime(environment, adapters)

    assert first is second
    assert len(captured) == 1
    assert set(captured[0][1]) == EXECUTORS
    assert set(captured[0][2]) == PROBES


@pytest.mark.parametrize("missing", sorted(EXECUTORS))
def test_install_runtime_rejects_missing_adapter(monkeypatch, missing):
    monkeypatch.setattr(startup, "_installed_dispatcher", None)
    environment = {name: lambda _inputs: True for name in PROBES}
    adapters = {name: ClosedAdapter() for name in EXECUTORS - {missing}}
    with pytest.raises(RuntimeError, match="adapters incomplete"):
        startup.install_deskpilot_runtime(environment, adapters)


@pytest.mark.parametrize("missing", sorted(PROBES))
def test_install_runtime_rejects_missing_probe(monkeypatch, missing):
    monkeypatch.setattr(startup, "_installed_dispatcher", None)
    environment = {name: lambda _inputs: True for name in PROBES - {missing}}
    adapters = {name: ClosedAdapter() for name in EXECUTORS}
    with pytest.raises(RuntimeError, match="probes incomplete"):
        startup.install_deskpilot_runtime(environment, adapters)
