import hashlib
import json

import pytest

from deskpilot_hermes.integration import (
    ACTION_EXECUTORS,
    TOOL_ACTIONS,
    AdmittedRequest,
    admit_scheduled,
    admit_sender,
    guarded_tool_call,
)
from deskpilot_hermes.policy import PolicyReply
from deskpilot_hermes.provenance import DeskPilotProvenance, provenance


class FakePolicy:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        return self.replies.pop(0)


def admitted_reply(admission_id="admission-1"):
    return PolicyReply(
        {"admitted": True, "admissionID": admission_id}, "policy.ok", "ok"
    )


def authorization(verdict="allow", **extra):
    result = {
        "decision": {"verdict": verdict, "ruleID": "decision.rule", "reason": "reason"},
        "actionDigest": "sha256:digest",
    }
    result.update(extra)
    return PolicyReply(result, "policy.ok", "ok")


def test_tool_mapping_and_executor_contract_is_exact():
    assert TOOL_ACTIONS == {
        "hs_app_observe": ("app.observe", 1),
        "hs_app_focus": ("app.focus", 1),
        "hs_window_place": ("window.place", 1),
        "hs_zed_command_palette": ("zed.commandPalette", 1),
        "hs_ghostty_new_tab": ("ghostty.newTab", 1),
        "browser_open": ("browser.open", 1),
        "cua_observe": ("cua.observe", 1),
        "cua_focus": ("cua.focus", 1),
        "cua_click": ("cua.click", 1),
        "cua_type": ("cua.type", 1),
        "terminal_diagnostic": ("terminal.diagnostic", 1),
        "file_reveal": ("file.reveal", 1),
        "file_move": ("file.move", 1),
        "message_send": ("message.send", 1),
        "credential_change": ("credential.change", 1),
        "shell_destructive": ("shell.destructive", 1),
        "health_observe": ("health.observe", 1),
        "developer_digest": ("developer.digest", 1),
    }
    assert ACTION_EXECUTORS == {
        "app.observe": "hammerspoon",
        "app.focus": "hammerspoon",
        "window.place": "hammerspoon",
        "zed.commandPalette": "hammerspoon",
        "ghostty.newTab": "hammerspoon",
        "browser.open": "browseros",
        "message.send": "browseros",
        "credential.change": "browseros",
        "cua.observe": "cua",
        "cua.focus": "cua",
        "cua.click": "cua",
        "cua.type": "cua",
        "terminal.diagnostic": "terminal",
        "shell.destructive": "terminal",
        "health.observe": "terminal",
        "file.reveal": "file",
        "file.move": "file",
        "developer.digest": "file",
    }


@pytest.mark.parametrize(
    ("platform", "sender_id", "canonical"),
    [
        ("telegram", "100000001", "telegram:100000001"),
        ("signal", "+27820000000", "signal:+27820000000"),
        ("signal", "account:Alice_123", "signal:account:Alice_123"),
    ],
)
def test_sender_is_admitted_before_agent_construction(platform, sender_id, canonical):
    events = []
    policy = FakePolicy([admitted_reply()])

    result = admit_sender(
        policy,
        platform,
        sender_id,
        lambda admitted: events.append(("construct", admitted)) or "agent",
    )

    assert result == "agent"
    assert policy.calls == [
        (
            "admit",
            {
                "entryPoint": platform,
                "sender": canonical,
                "uiLease": None,
                "jobID": None,
                "actionID": None,
                "actionVersion": 1,
                "inputDigest": None,
            },
        )
    ]
    assert events[0][0] == "construct"
    request = events[0][1]
    assert request.admission_id == "admission-1"
    assert request.provenance.entry_point == platform
    assert request.provenance.sender == canonical
    assert request.provenance.trace_id


@pytest.mark.parametrize(
    ("platform", "sender_id"),
    [
        ("telegram", "0"),
        ("telegram", "+27"),
        ("telegram", "01"),
        ("signal", "27820000000"),
        ("signal", "+012345678"),
        ("signal", "account:short"),
        ("discord", "123"),
    ],
)
def test_invalid_or_unknown_sender_is_denied_before_policy_call(platform, sender_id):
    policy = FakePolicy([])
    constructed = []
    assert admit_sender(policy, platform, sender_id, constructed.append) is None
    assert policy.calls == []
    assert constructed == []


def test_socket_denial_constructs_no_agent():
    policy = FakePolicy([PolicyReply(None, "policy.transport_denied", "OSError")])
    constructed = []
    assert admit_sender(policy, "signal", "+27820000000", constructed.append) is None
    assert constructed == []


def test_sender_requires_exact_admitted_shape_and_nonempty_admission_id():
    for result in (
        {"admitted": 1, "admissionID": "a"},
        {"admitted": True, "admissionID": ""},
        {"admitted": True},
        None,
    ):
        policy = FakePolicy([PolicyReply(result, "policy.ok", "ok")])
        assert admit_sender(policy, "telegram", "42", lambda _: "agent") is None


def test_malformed_sender_policy_reply_fails_closed():
    constructed = []
    assert (
        admit_sender(FakePolicy([None]), "telegram", "42", constructed.append) is None
    )
    assert constructed == []


def test_scheduler_verifies_exact_compiled_envelope_before_admission():
    inputs = {"probe": "health", "count": 2}
    digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    policy = FakePolicy([admitted_reply()])

    admitted = admit_scheduled(
        policy,
        {
            "jobID": "health.exception",
            "actionID": "health.observe",
            "actionVersion": 1,
            "inputDigest": digest,
            "inputs": inputs,
        },
    )

    assert admitted is not None
    assert admitted.provenance.entry_point == "scheduler"
    assert policy.calls == [
        (
            "admit",
            {
                "entryPoint": "scheduler",
                "sender": "job:health.exception",
                "uiLease": None,
                "jobID": "health.exception",
                "actionID": "health.observe",
                "actionVersion": 1,
                "inputDigest": digest,
            },
        )
    ]


@pytest.mark.parametrize(
    "compiled",
    [
        {},
        {
            "jobID": "job",
            "actionID": "health.observe",
            "actionVersion": True,
            "inputDigest": "sha256:x",
            "inputs": {},
        },
        {
            "jobID": "",
            "actionID": "health.observe",
            "actionVersion": 1,
            "inputDigest": "sha256:x",
            "inputs": {},
        },
        {
            "jobID": "job",
            "actionID": "",
            "actionVersion": 1,
            "inputDigest": "sha256:x",
            "inputs": {},
        },
        {
            "jobID": "job",
            "actionID": "health.observe",
            "actionVersion": 1,
            "inputDigest": "sha256:x",
            "inputs": [],
        },
        {
            "jobID": "job",
            "actionID": "health.observe",
            "actionVersion": 1,
            "inputDigest": "sha256:changed",
            "inputs": {},
        },
        {
            "jobID": "job",
            "actionID": "health.observe",
            "actionVersion": 1,
            "inputDigest": "sha256:x",
            "inputs": {},
            "extra": None,
        },
    ],
)
def test_malformed_scheduler_envelope_is_denied_before_policy_call(compiled):
    policy = FakePolicy([])
    assert admit_scheduled(policy, compiled) is None
    assert policy.calls == []


def test_malformed_scheduler_policy_reply_fails_closed():
    inputs = {}
    digest = "sha256:" + hashlib.sha256(b"{}").hexdigest()
    assert (
        admit_scheduled(
            FakePolicy([None]),
            {
                "jobID": "job",
                "actionID": "health.observe",
                "actionVersion": 1,
                "inputDigest": digest,
                "inputs": inputs,
            },
        )
        is None
    )


def test_guarded_allow_authorizes_executes_then_invokes_once():
    prov = DeskPilotProvenance("ui", None, "trace-1")
    admitted = AdmittedRequest(prov, "admission-1")
    policy = FakePolicy([
        authorization(),
        PolicyReply({"execute": True}, "policy.ok", "ok"),
    ])
    invoked = []

    with provenance(prov):
        value, reply = guarded_tool_call(
            policy,
            admitted,
            "cua_click",
            {"x": 1},
            lambda: invoked.append("invoke") or "done",
            lambda _: pytest.fail("allow must not request local approval"),
        )

    assert value == "done" and reply.allowed and invoked == ["invoke"]
    assert policy.calls == [
        (
            "authorize",
            {
                "admissionID": "admission-1",
                "traceID": "trace-1",
                "actionID": "cua.click",
                "actionVersion": 1,
                "inputs": {"x": 1},
            },
        ),
        (
            "execute",
            {
                "admissionID": "admission-1",
                "traceID": "trace-1",
                "actionDigest": "sha256:digest",
                "confirmationCapability": None,
            },
        ),
    ]


@pytest.mark.parametrize(
    "reply",
    [
        PolicyReply(None, "policy.transport_denied", "TimeoutError"),
        PolicyReply({}, "policy.ok", "ok"),
        PolicyReply({"decision": None, "actionDigest": "sha256:x"}, "policy.ok", "ok"),
        PolicyReply(
            {"decision": {"verdict": "maybe"}, "actionDigest": "sha256:x"},
            "policy.ok",
            "ok",
        ),
        PolicyReply({"decision": {"verdict": "allow"}}, "policy.ok", "ok"),
    ],
)
def test_transport_or_malformed_authorization_never_invokes(reply):
    prov = DeskPilotProvenance("ui", None, "trace-1")
    invoked = []
    with provenance(prov):
        value, denied = guarded_tool_call(
            FakePolicy([reply]),
            AdmittedRequest(prov, "a"),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda _: "capability",
        )
    assert value is None and denied.result is None and invoked == []


def test_deny_uses_policy_decision_and_never_invokes():
    prov = DeskPilotProvenance("ui", None, "trace-1")
    invoked = []
    with provenance(prov):
        value, reply = guarded_tool_call(
            FakePolicy([authorization("deny")]),
            AdmittedRequest(prov, "a"),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda _: "cap",
        )
    assert value is None and (reply.rule_id, reply.reason) == (
        "decision.rule",
        "reason",
    )
    assert invoked == []


@pytest.mark.parametrize("verdict", ["ask", "local_confirm"])
def test_local_confirmation_failure_and_remote_response_never_invoke(verdict):
    prov = DeskPilotProvenance("telegram", "telegram:42", "trace-1")
    auth = authorization(
        verdict,
        pendingApprovalID="pending-1",
        confirmationCapability="remote-must-not-count",
    )
    callbacks = []
    invoked = []
    with provenance(prov):
        value, reply = guarded_tool_call(
            FakePolicy([auth]),
            AdmittedRequest(prov, "a"),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda result: callbacks.append(result),
        )
    assert value is None and reply.rule_id == "policy.approval_denied"
    assert callbacks == [auth.result]
    assert invoked == []


@pytest.mark.parametrize("verdict", ["ask", "local_confirm"])
def test_ask_resumes_only_with_nonempty_supplied_local_capability(verdict):
    prov = DeskPilotProvenance("telegram", "telegram:42", "trace-1")
    policy = FakePolicy([
        authorization(verdict, pendingApprovalID="pending-1"),
        PolicyReply({"execute": True}, "policy.ok", "ok"),
    ])
    invoked = []
    with provenance(prov):
        value, _ = guarded_tool_call(
            policy,
            AdmittedRequest(prov, "a"),
            "cua_click",
            {},
            lambda: invoked.append(True) or "done",
            lambda _: "local-capability",
        )
    assert value == "done" and invoked == [True]
    assert policy.calls[1][1]["confirmationCapability"] == "local-capability"


@pytest.mark.parametrize("capability", [None, "", 7])
def test_missing_or_invalid_local_capability_denies(capability):
    prov = DeskPilotProvenance("ui", None, "trace-1")
    invoked = []
    with provenance(prov):
        value, _ = guarded_tool_call(
            FakePolicy([authorization("ask")]),
            AdmittedRequest(prov, "a"),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda _: capability,
        )
    assert value is None and invoked == []


@pytest.mark.parametrize(
    "grant",
    [
        PolicyReply(None, "policy.transport_denied", "OSError"),
        PolicyReply({}, "policy.ok", "ok"),
        PolicyReply({"execute": 1}, "policy.ok", "ok"),
        PolicyReply({"execute": False}, "policy.ok", "ok"),
    ],
)
def test_execute_requires_literal_true_before_invocation(grant):
    prov = DeskPilotProvenance("ui", None, "trace-1")
    invoked = []
    with provenance(prov):
        value, reply = guarded_tool_call(
            FakePolicy([authorization(), grant]),
            AdmittedRequest(prov, "a"),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda _: None,
        )
    assert value is None and not reply.allowed and invoked == []


def test_missing_current_provenance_denies_without_policy_or_invocation():
    prov = DeskPilotProvenance("ui", None, "trace-1")
    policy = FakePolicy([])
    invoked = []
    value, reply = guarded_tool_call(
        policy,
        AdmittedRequest(prov, "a"),
        "cua_click",
        {},
        lambda: invoked.append(True),
        lambda _: None,
    )
    assert value is None and reply.rule_id == "policy.provenance_denied"
    assert policy.calls == [] and invoked == []


def test_provenance_mismatch_unmapped_tool_and_bad_arguments_deny_without_policy():
    current = DeskPilotProvenance("ui", None, "trace-current")
    admitted = AdmittedRequest(DeskPilotProvenance("ui", None, "trace-other"), "a")
    for tool_name, arguments in (("cua_click", {}), ("unknown", {}), ("cua_click", [])):
        policy = FakePolicy([])
        with provenance(current):
            value, reply = guarded_tool_call(
                policy,
                admitted if tool_name != "unknown" else AdmittedRequest(current, "a"),
                tool_name,
                arguments,
                lambda: pytest.fail("must not invoke"),
                lambda _: None,
            )
        assert value is None and reply.result is None and policy.calls == []
