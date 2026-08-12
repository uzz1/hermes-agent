import inspect
import json
from types import SimpleNamespace

import model_tools

from deskpilot_hermes.integration import AdmittedRequest
from deskpilot_hermes.provenance import DeskPilotProvenance
from deskpilot_hermes.runtime_context import (
    reset_admitted_request,
    reset_tool_dispatcher,
    set_admitted_request,
    set_tool_dispatcher,
)


ADMITTED = AdmittedRequest(
    DeskPilotProvenance("ui", "local:user", "b4783542-8cc5-4b03-a43f-239445405eed"),
    "a399f2e8-c425-49d7-9f90-67d46c436aa0",
)


class FakeDispatcher:
    def __init__(self, result=None, error=None):
        self.result = result or {"observed": True}
        self.error = error
        self.calls = []

    def dispatch(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


def test_ordinary_mode_forwards_every_signature_field_exactly(monkeypatch):
    captured = []
    public_signature = inspect.signature(model_tools.handle_function_call)
    unchecked_signature = inspect.signature(model_tools._handle_function_call_unchecked)

    def unchecked(**kwargs):
        captured.append(kwargs)
        return "ordinary"

    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    monkeypatch.setattr(model_tools, "_handle_function_call_unchecked", unchecked)
    values = {
        "function_name": "dummy",
        "function_args": {"value": 1},
        "task_id": "task",
        "tool_call_id": "call",
        "session_id": "session",
        "turn_id": "turn",
        "api_request_id": "request",
        "user_task": "user task",
        "enabled_tools": ["dummy"],
        "skip_pre_tool_call_hook": True,
        "skip_tool_request_middleware": True,
        "tool_request_middleware_trace": [{"middleware": "one"}],
        "enabled_toolsets": ["core"],
        "disabled_toolsets": ["web"],
    }

    assert model_tools.handle_function_call(**values) == "ordinary"
    assert captured == [values]
    assert public_signature == unchecked_signature


def test_deskpilot_mode_dispatches_named_policy_fields_only(monkeypatch):
    unchecked = []
    dispatcher = FakeDispatcher({"observed": True, "value": 2})
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        model_tools,
        "_handle_function_call_unchecked",
        lambda **kwargs: unchecked.append(kwargs),
    )
    admitted_token = set_admitted_request(ADMITTED)
    dispatcher_token = set_tool_dispatcher(dispatcher)
    try:
        result = model_tools.handle_function_call(
            "browser_open",
            {"url": "https://example.com"},
            "task",
            tool_call_id="call",
            session_id="session",
            turn_id="turn",
            api_request_id="request",
            user_task="caller metadata",
            enabled_tools=["browser_open"],
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            tool_request_middleware_trace=[{"secret": True}],
            enabled_toolsets=["deskpilot"],
            disabled_toolsets=["terminal"],
        )
    finally:
        reset_tool_dispatcher(dispatcher_token)
        reset_admitted_request(admitted_token)

    assert result == '{"observed":true,"value":2}'
    assert dispatcher.calls == [
        {
            "admitted": ADMITTED,
            "tool_name": "browser_open",
            "arguments": {"url": "https://example.com"},
        }
    ]
    assert unchecked == []


def test_missing_context_or_dispatcher_error_fails_closed_without_unchecked(
    monkeypatch,
):
    unchecked = []
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        model_tools,
        "_handle_function_call_unchecked",
        lambda **kwargs: unchecked.append(kwargs),
    )

    missing = model_tools.handle_function_call("browser_open", {})
    assert json.loads(missing) == {
        "ok": False,
        "error": "deskpilot.policy_denied",
        "_meta": {
            "deskpilot": {
                "ruleID": "execute.denied",
                "reason": "PermissionError",
            }
        },
    }

    admitted_token = set_admitted_request(ADMITTED)
    dispatcher_token = set_tool_dispatcher(FakeDispatcher(error=RuntimeError("no")))
    try:
        failed = model_tools.handle_function_call("browser_open", {})
    finally:
        reset_tool_dispatcher(dispatcher_token)
        reset_admitted_request(admitted_token)
    assert failed == (
        '{"ok":false,"error":"deskpilot.policy_denied",'
        '"_meta":{"deskpilot":{"ruleID":"execute.denied",'
        '"reason":"RuntimeError"}}}'
    )
    assert unchecked == []


def test_actual_tool_executor_call_shape_reaches_checked_dispatch(monkeypatch):
    from agent import tool_executor

    dispatcher = FakeDispatcher()
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(tool_executor, "_ra", lambda: model_tools)
    monkeypatch.setattr(
        tool_executor,
        "_apply_tool_request_middleware_for_agent",
        lambda _agent, **kwargs: (kwargs["function_args"], []),
    )
    monkeypatch.setattr(tool_executor, "_detect_tool_failure", lambda *_: (False, None))
    monkeypatch.setattr(tool_executor, "get_active_env", lambda _task_id: None)
    monkeypatch.setattr(
        tool_executor,
        "maybe_persist_tool_result",
        lambda *, content, **_kwargs: content,
    )
    monkeypatch.setattr(tool_executor, "enforce_turn_budget", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        "hermes_cli.plugins.get_pre_tool_call_block_message",
        lambda *_a, **_kw: None,
    )
    monkeypatch.setattr(
        "agent.agent_runtime_helpers.agent_runtime_owns_post_tool_hook",
        lambda *_: False,
    )
    monkeypatch.setattr("tools.environments.base.set_activity_callback", lambda _: None)

    agent = SimpleNamespace(
        _interrupt_requested=False,
        _tool_guardrails=SimpleNamespace(
            before_call=lambda *_: SimpleNamespace(allows_execution=True)
        ),
        quiet_mode=True,
        verbose_logging=False,
        _current_tool=None,
        _touch_activity=lambda *_: None,
        tool_progress_callback=None,
        tool_start_callback=None,
        tool_complete_callback=None,
        _context_engine_tool_names=frozenset(),
        _memory_manager=None,
        session_id="session-id",
        _current_turn_id="turn-id",
        _current_api_request_id="request-id",
        valid_tool_names={"browser_open"},
        enabled_toolsets=["deskpilot"],
        disabled_toolsets=["web"],
        _should_emit_quiet_tool_messages=lambda: False,
        _should_start_quiet_spinner=lambda: False,
        _append_guardrail_observation=lambda _name, _args, result, **_kw: result,
        _record_file_mutation_result=lambda *_a, **_kw: None,
        _subdirectory_hints=SimpleNamespace(check_tool_call=lambda *_: ""),
        _tool_result_content_for_active_model=lambda _name, result: result,
        _apply_pending_steer_to_tool_results=lambda *_: None,
        tool_delay=0,
        log_prefix="",
        _vprint=lambda *_a, **_kw: None,
    )
    call = SimpleNamespace(
        id="tool-call-id",
        function=SimpleNamespace(
            name="browser_open", arguments='{"url":"https://example.com"}'
        ),
    )
    assistant = SimpleNamespace(tool_calls=[call])
    messages = []
    admitted_token = set_admitted_request(ADMITTED)
    dispatcher_token = set_tool_dispatcher(dispatcher)
    try:
        tool_executor.execute_tool_calls_sequential(
            agent, assistant, messages, "task-id"
        )
    finally:
        reset_tool_dispatcher(dispatcher_token)
        reset_admitted_request(admitted_token)

    assert dispatcher.calls == [
        {
            "admitted": ADMITTED,
            "tool_name": "browser_open",
            "arguments": {"url": "https://example.com"},
        }
    ]
    assert json.loads(messages[0]["content"]) == {"observed": True}
