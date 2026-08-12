from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from deskpilot.actions import ActionRegistry
from deskpilot.execution import ExecutionDenied, action_digest
from deskpilot_hermes.integration import AdmittedRequest
from deskpilot_hermes.policy import PolicyReply
from deskpilot_hermes.provenance import DeskPilotProvenance
from deskpilot_hermes.tool_dispatcher import DeskPilotToolDispatcher


ADMISSION_ID = "a399f2e8-c425-49d7-9f90-67d46c436aa0"
TRACE_ID = "b4783542-8cc5-4b03-a43f-239445405eed"
PENDING_ID = "74e96407-e06c-4784-825f-36315b0be447"
CONSUMPTION_ID = "d10f4f35-18b8-48e9-a146-4e70f82ea19b"
ARGS = {"url": "https://example.com"}
DIGEST = action_digest("browser.open", 1, ARGS)


def authorization(verdict="allow", **changes):
    result = {
        "decision": {
            "risk": "reversible_local",
            "verdict": verdict,
            "ruleID": f"authorize.{verdict}",
            "reason": verdict,
        },
        "actionDigest": None if verdict == "deny" else DIGEST,
        "pendingApprovalID": PENDING_ID
        if verdict in {"ask", "local_confirm"}
        else None,
        "expiresAt": (datetime.now(UTC) + timedelta(seconds=60)).isoformat()
        if verdict in {"ask", "local_confirm"}
        else None,
    }
    result.update(changes)
    return PolicyReply(result, "policy.ok", "ok")


def execution(execute=True, **changes):
    result = {
        "execute": execute,
        "consumptionID": CONSUMPTION_ID if execute else None,
        "ruleID": "execute.allowed" if execute else "execute.denied",
        "reason": "executed" if execute else "denied",
    }
    result.update(changes)
    return PolicyReply(result, "policy.ok", "ok")


class FakePolicy:
    def __init__(self, replies, *, on_call=None):
        self.replies = list(replies)
        self.calls = []
        self.on_call = on_call

    def call(self, method, params):
        self.calls.append((method, deepcopy(params)))
        if self.on_call is not None:
            self.on_call(method, params)
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


class ClosedAdapter:
    def __init__(self, name, events=None, result=None, error=None):
        self.name = name
        self.events = events if events is not None else []
        self.result = result or {"browser_url_matches": True}
        self.error = error
        self.calls = []

    def execute(self, action_id, inputs):
        self.events.append("adapter")
        self.calls.append((action_id, deepcopy(inputs)))
        if self.error is not None:
            raise self.error
        return self.result


def adapters(browser=None):
    return {
        name: browser
        if name == "browseros" and browser is not None
        else ClosedAdapter(name)
        for name in ("hammerspoon", "browseros", "cua", "terminal", "file")
    }


def admitted(entry_point="ui"):
    return AdmittedRequest(
        DeskPilotProvenance(entry_point, None, TRACE_ID), ADMISSION_ID
    )


def dispatcher(policy, *, browser=None, approval=lambda _auth: "capability-1"):
    return DeskPilotToolDispatcher(
        policy,
        adapters(browser),
        {"browseros_ready": lambda _inputs: True},
        approval,
    )


def test_dispatch_uses_parent_registry_and_exposes_no_raw_invoke_api():
    policy = FakePolicy([authorization(), execution()])
    tool_dispatcher = dispatcher(policy)

    assert ActionRegistry.__module__ == "deskpilot.actions"
    assert not hasattr(tool_dispatcher, "invoke")
    assert not hasattr(tool_dispatcher, "_handle_function_call_unchecked")
    assert all(
        not hasattr(adapter, "invoke") for adapter in tool_dispatcher._adapters.values()
    )


@pytest.mark.parametrize(
    "bad_adapters",
    [
        {},
        {"hammerspoon": ClosedAdapter("hammerspoon")},
        {**adapters(), "extra": ClosedAdapter("extra")},
    ],
)
def test_constructor_requires_exact_adapter_keys(bad_adapters):
    with pytest.raises(ValueError):
        DeskPilotToolDispatcher(FakePolicy([]), bad_adapters, {}, lambda _: None)


def test_actions_resource_fallback_requires_declared_distribution_file(
    monkeypatch, tmp_path
):
    import deskpilot_hermes.tool_dispatcher as module

    actions = tmp_path / "actions.yaml"
    actions.write_text("actions: []\n")

    class MissingResource:
        def joinpath(self, *_parts):
            return self

        def is_file(self):
            return False

    class Distribution:
        files = [Path("deskpilot/data/actions.yaml")]

        def locate_file(self, declared):
            assert str(declared) == "deskpilot/data/actions.yaml"
            return actions

    monkeypatch.setattr(module.resources, "files", lambda _package: MissingResource())
    monkeypatch.setattr(module.metadata, "distribution", lambda _name: Distribution())
    assert module._packaged_actions_path() == actions

    Distribution.files = []
    with pytest.raises(FileNotFoundError):
        module._packaged_actions_path()


@pytest.mark.parametrize("attribute", ["invoke", "_handle_function_call_unchecked"])
def test_constructor_rejects_adapters_with_raw_dispatch_api(attribute):
    bad = ClosedAdapter("browseros")
    setattr(bad, attribute, lambda *_: None)
    with pytest.raises(ValueError):
        DeskPilotToolDispatcher(FakePolicy([]), adapters(bad), {}, lambda _: None)


def test_success_sends_exact_policy_calls_and_runs_pre_adapter_post(monkeypatch):
    import deskpilot_hermes.tool_dispatcher as module

    events = []
    monkeypatch.setitem(
        module.PRECONDITIONS,
        "browseros_ready",
        lambda _context: events.append("pre") or True,
    )
    monkeypatch.setitem(
        module.POSTCONDITIONS,
        "browser_url_matches",
        lambda _observed: events.append("post") or True,
    )
    browser = ClosedAdapter(
        "browseros", events, {"browser_url_matches": True, "observed": "exact"}
    )
    policy = FakePolicy([authorization(), execution()])

    result = dispatcher(policy, browser=browser).dispatch(
        admitted=admitted(), tool_name="browser_open", arguments=ARGS
    )

    assert result is browser.result
    assert events == ["pre", "adapter", "post"]
    assert policy.calls == [
        (
            "authorize",
            {
                "admissionID": ADMISSION_ID,
                "traceID": TRACE_ID,
                "actionID": "browser.open",
                "actionVersion": 1,
                "inputs": ARGS,
            },
        ),
        (
            "execute",
            {
                "admissionID": ADMISSION_ID,
                "traceID": TRACE_ID,
                "actionDigest": DIGEST,
                "confirmationCapability": None,
            },
        ),
    ]


def test_inputs_are_detached_from_caller_and_policy_mutation():
    caller_args = dict(ARGS)

    def mutate_authorize(method, params):
        if method == "authorize":
            params["inputs"]["url"] = "https://mutated.invalid"

    browser = ClosedAdapter("browseros")
    policy = FakePolicy([authorization(), execution()], on_call=mutate_authorize)
    dispatcher(policy, browser=browser).dispatch(
        admitted=admitted(), tool_name="browser_open", arguments=caller_args
    )

    caller_args["url"] = "https://changed.invalid"
    assert browser.calls == [("browser.open", ARGS)]


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [("unknown", ARGS), ("browser_open", {}), ("browser_open", {"url": "http://x"})],
)
def test_unmapped_or_invalid_action_denies_before_policy(tool_name, arguments):
    policy = FakePolicy([])
    with pytest.raises(ExecutionDenied):
        dispatcher(policy).dispatch(admitted(), tool_name, arguments)
    assert policy.calls == []


@pytest.mark.parametrize("bad_admitted", [None, object()])
def test_dispatch_requires_admitted_request_and_dict_arguments(bad_admitted):
    policy = FakePolicy([])
    with pytest.raises(ExecutionDenied):
        dispatcher(policy).dispatch(bad_admitted, "browser_open", ARGS)
    with pytest.raises(ExecutionDenied):
        dispatcher(policy).dispatch(admitted(), "browser_open", [])
    assert policy.calls == []


@pytest.mark.parametrize(
    "reply",
    [
        RuntimeError("socket"),
        None,
        PolicyReply(None, "policy.transport_denied", "socket"),
        PolicyReply({"decision": {}}, "policy.ok", "ok"),
        authorization(extra=True),
    ],
)
def test_authorization_transport_or_malformed_reply_denies_without_adapter(reply):
    browser = ClosedAdapter("browseros")
    with pytest.raises(ExecutionDenied):
        dispatcher(FakePolicy([reply]), browser=browser).dispatch(
            admitted(), "browser_open", ARGS
        )
    assert browser.calls == []


def test_policy_deny_never_executes_or_requests_approval():
    approvals = []
    browser = ClosedAdapter("browseros")
    policy = FakePolicy([authorization("deny")])
    with pytest.raises(ExecutionDenied):
        dispatcher(
            policy, browser=browser, approval=lambda value: approvals.append(value)
        ).dispatch(admitted(), "browser_open", ARGS)
    assert browser.calls == []
    assert approvals == []
    assert [method for method, _ in policy.calls] == ["authorize"]


def test_local_confirm_requires_ui_but_ask_can_approve_remote():
    approvals = []
    local = FakePolicy([authorization("local_confirm")])
    with pytest.raises(ExecutionDenied):
        dispatcher(local, approval=lambda value: approvals.append(value)).dispatch(
            admitted("telegram"), "browser_open", ARGS
        )
    assert approvals == []

    ask = authorization("ask")
    remote = FakePolicy([ask, execution()])
    result = dispatcher(
        remote, approval=lambda value: approvals.append(value) or "capability-1"
    ).dispatch(admitted("telegram"), "browser_open", ARGS)
    assert result == {"browser_url_matches": True}
    assert approvals == [ask.result]
    assert remote.calls[1][1]["confirmationCapability"] == "capability-1"


@pytest.mark.parametrize("approval_result", [None, "", 1])
def test_approval_failure_denies_before_execute(approval_result):
    policy = FakePolicy([authorization("ask")])
    with pytest.raises(ExecutionDenied):
        dispatcher(policy, approval=lambda _auth: approval_result).dispatch(
            admitted(), "browser_open", ARGS
        )
    assert [method for method, _ in policy.calls] == ["authorize"]


@pytest.mark.parametrize(
    "reply",
    [
        RuntimeError("socket"),
        None,
        PolicyReply(None, "policy.transport_denied", "socket"),
        execution(False),
        execution(extra=True),
        execution(consumptionID=CONSUMPTION_ID.upper()),
    ],
)
def test_execute_denial_or_malformed_reply_never_calls_adapter(reply):
    browser = ClosedAdapter("browseros")
    policy = FakePolicy([authorization(), reply])
    with pytest.raises(ExecutionDenied):
        dispatcher(policy, browser=browser).dispatch(admitted(), "browser_open", ARGS)
    assert browser.calls == []


@pytest.mark.parametrize("mode", ["false", "raise"])
def test_precondition_failure_denies_before_adapter(monkeypatch, mode):
    import deskpilot_hermes.tool_dispatcher as module

    def check(_context):
        if mode == "raise":
            raise RuntimeError("pre")
        return False

    monkeypatch.setitem(module.PRECONDITIONS, "browseros_ready", check)
    browser = ClosedAdapter("browseros")
    with pytest.raises(ExecutionDenied):
        dispatcher(
            FakePolicy([authorization(), execution()]), browser=browser
        ).dispatch(admitted(), "browser_open", ARGS)
    assert browser.calls == []


def test_adapter_exception_is_normalized_to_execution_denied():
    browser = ClosedAdapter("browseros", error=RuntimeError("adapter secret"))
    with pytest.raises(ExecutionDenied) as raised:
        dispatcher(
            FakePolicy([authorization(), execution()]), browser=browser
        ).dispatch(admitted(), "browser_open", ARGS)
    assert "adapter secret" not in str(raised.value)
    assert len(browser.calls) == 1


@pytest.mark.parametrize("mode", ["false", "raise"])
def test_postcondition_failure_records_adapter_once_but_never_succeeds(
    monkeypatch, mode
):
    import deskpilot_hermes.tool_dispatcher as module

    def check(_observed):
        if mode == "raise":
            raise RuntimeError("post")
        return False

    monkeypatch.setitem(module.POSTCONDITIONS, "browser_url_matches", check)
    browser = ClosedAdapter("browseros")
    with pytest.raises(ExecutionDenied):
        dispatcher(
            FakePolicy([authorization(), execution()]), browser=browser
        ).dispatch(admitted(), "browser_open", ARGS)
    assert len(browser.calls) == 1
