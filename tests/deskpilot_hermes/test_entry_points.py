import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

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


PENDING_ID = "74e96407-e06c-4784-825f-36315b0be447"
ACTION_DIGEST = "sha256:" + "a" * 64
CONSUMPTION_ID = "d10f4f35-18b8-48e9-a146-4e70f82ea19b"
ADMISSION_ID = "a399f2e8-c425-49d7-9f90-67d46c436aa0"
TRACE_ID = "b4783542-8cc5-4b03-a43f-239445405eed"


class FakePolicy:
    def __init__(self, replies, on_call=None):
        self.replies = list(replies)
        self.calls = []
        self.on_call = on_call

    def call(self, method, params):
        self.calls.append((method, params))
        if self.on_call is not None:
            self.on_call(method, params)
        return self.replies.pop(0)


def admitted_reply(
    admission_id=ADMISSION_ID,
    entry_point="telegram",
    sender="telegram:100000001",
    **extra,
):
    result = {
        "admitted": True,
        "ruleID": "admit.allowed",
        "reason": "admitted",
        "admissionID": admission_id,
        "entryPoint": entry_point,
        "sender": sender,
        "principal": "principal-1",
        "expiresAt": (datetime.now(UTC) + timedelta(seconds=60)).isoformat(),
    }
    result.update(extra)
    return PolicyReply(result, "policy.ok", "ok")


def denied_admission(entry_point="telegram", sender="telegram:100000001"):
    return PolicyReply(
        {
            "admitted": False,
            "ruleID": "admit.denied",
            "reason": "denied",
            "admissionID": None,
            "entryPoint": entry_point,
            "sender": sender,
            "principal": None,
            "expiresAt": None,
        },
        "policy.ok",
        "ok",
    )


def authorization(verdict="allow", **extra):
    result = {
        "decision": {
            "risk": "mutation",
            "verdict": verdict,
            "ruleID": "decision.rule",
            "reason": "reason",
        },
        "actionDigest": None if verdict == "deny" else ACTION_DIGEST,
        "pendingApprovalID": PENDING_ID
        if verdict in {"ask", "local_confirm"}
        else None,
        "expiresAt": (datetime.now(UTC) + timedelta(seconds=60)).isoformat()
        if verdict in {"ask", "local_confirm"}
        else None,
    }
    result.update(extra)
    return PolicyReply(result, "policy.ok", "ok")


def execution(execute=True, **extra):
    result = {
        "execute": execute,
        "consumptionID": CONSUMPTION_ID if execute else None,
        "ruleID": "execute.allowed" if execute else "execute.denied",
        "reason": "executed" if execute else "denied",
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
    policy = FakePolicy([admitted_reply(entry_point=platform, sender=canonical)])

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
    assert request.admission_id == ADMISSION_ID
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
    for result in ({"admitted": 1, "admissionID": "a"}, None):
        policy = FakePolicy([PolicyReply(result, "policy.ok", "ok")])
        assert admit_sender(policy, "telegram", "42", lambda _: "agent") is None


def _malformed_admission_replies():
    cases = []

    def changed(**updates):
        result = deepcopy(admitted_reply().result)
        result.update(updates)
        return PolicyReply(result, "policy.ok", "ok")

    cases.extend([
        changed(extra=True),
        changed(admitted=1),
        changed(ruleID=""),
        changed(reason=""),
        changed(admissionID=""),
        changed(admissionID=ADMISSION_ID.upper()),
        changed(entryPoint="signal"),
        changed(sender="telegram:999"),
        changed(principal=None),
        changed(principal=""),
        changed(expiresAt=None),
        changed(expiresAt="not-rfc3339"),
        changed(expiresAt="2099-08-12T12:00:00"),
        changed(expiresAt="2099-08-12 12:00:00+00:00"),
        changed(expiresAt=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()),
        changed(expiresAt=(datetime.now(UTC) + timedelta(seconds=301)).isoformat()),
    ])
    denied = deepcopy(denied_admission().result)
    denied["admissionID"] = "unexpected"
    cases.append(PolicyReply(denied, "policy.ok", "ok"))
    denied = deepcopy(denied_admission().result)
    denied["principal"] = "unexpected"
    cases.append(PolicyReply(denied, "policy.ok", "ok"))
    denied = deepcopy(denied_admission().result)
    denied["expiresAt"] = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    cases.append(PolicyReply(denied, "policy.ok", "ok"))
    denied = deepcopy(denied_admission().result)
    denied["ruleID"] = ""
    cases.append(PolicyReply(denied, "policy.ok", "ok"))
    return cases


@pytest.mark.parametrize("reply", _malformed_admission_replies())
def test_sender_rejects_malformed_or_uncorrelated_admission_before_construction(reply):
    constructed = []
    result = admit_sender(
        FakePolicy([reply]), "telegram", "100000001", constructed.append
    )
    assert result is None and constructed == []


def test_correlated_admission_denial_constructs_no_agent():
    constructed = []
    result = admit_sender(
        FakePolicy([denied_admission()]),
        "telegram",
        "100000001",
        constructed.append,
    )
    assert result is None and constructed == []


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
    policy = FakePolicy([
        admitted_reply(entry_point="scheduler", sender="job:health.exception")
    ])

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


def test_scheduler_rejects_mismatched_admission_identity():
    digest = "sha256:" + hashlib.sha256(b"{}").hexdigest()
    policy = FakePolicy([
        admitted_reply(entry_point="scheduler", sender="job:other-job")
    ])
    assert (
        admit_scheduled(
            policy,
            {
                "jobID": "job",
                "actionID": "health.observe",
                "actionVersion": 1,
                "inputDigest": digest,
                "inputs": {},
            },
        )
        is None
    )


@pytest.mark.parametrize("nonfinite", [float("nan"), float("inf"), float("-inf")])
def test_scheduler_rejects_nonfinite_json_before_policy_call(nonfinite):
    inputs = {"value": nonfinite}
    permissive = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    policy = FakePolicy([])
    admitted = admit_scheduled(
        policy,
        {
            "jobID": "job",
            "actionID": "health.observe",
            "actionVersion": 1,
            "inputDigest": "sha256:" + hashlib.sha256(permissive).hexdigest(),
            "inputs": inputs,
        },
    )
    assert admitted is None
    assert policy.calls == []


def test_guarded_allow_authorizes_executes_then_invokes_once():
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    admitted = AdmittedRequest(prov, ADMISSION_ID)
    policy = FakePolicy([authorization(), execution()])
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
                "admissionID": ADMISSION_ID,
                "traceID": TRACE_ID,
                "actionID": "cua.click",
                "actionVersion": 1,
                "inputs": {"x": 1},
            },
        ),
        (
            "execute",
            {
                "admissionID": ADMISSION_ID,
                "traceID": TRACE_ID,
                "actionDigest": ACTION_DIGEST,
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
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    invoked = []
    with provenance(prov):
        value, denied = guarded_tool_call(
            FakePolicy([reply]),
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda _: "capability",
        )
    assert value is None and denied.result is None and invoked == []


def _malformed_authorizations():
    cases = []

    def changed(verdict="allow", **updates):
        value = deepcopy(authorization(verdict).result)
        value.update(updates)
        return PolicyReply(value, "policy.ok", "ok")

    cases.append(changed(extra=True))
    value = deepcopy(authorization().result)
    value["decision"]["extra"] = True
    cases.append(PolicyReply(value, "policy.ok", "ok"))
    for field, invalid in (
        ("risk", "unknown"),
        ("verdict", "unknown"),
        ("ruleID", ""),
        ("reason", ""),
    ):
        value = deepcopy(authorization().result)
        value["decision"][field] = invalid
        cases.append(PolicyReply(value, "policy.ok", "ok"))
    cases.extend([
        changed(pendingApprovalID=PENDING_ID),
        changed(expiresAt="2099-08-12T12:00:00Z"),
        changed(actionDigest=None),
        changed(actionDigest="sha256:digest"),
        changed(actionDigest="sha256:" + "A" * 64),
        changed(actionDigest="sha256:" + "a" * 63),
        changed("ask", pendingApprovalID="not-a-uuid"),
        changed("ask", expiresAt="not-rfc3339"),
        changed("ask", expiresAt="2099-08-12T12:00:00"),
        changed(
            "ask",
            expiresAt=(datetime.now(UTC) + timedelta(seconds=60))
            .isoformat()
            .replace("T", " "),
        ),
        changed("ask", pendingApprovalID=None),
        changed("ask", expiresAt=None),
        changed("deny", actionDigest="sha256:invalid"),
        changed("deny", pendingApprovalID=PENDING_ID),
        changed("deny", expiresAt="2099-08-12T12:00:00Z"),
    ])
    return cases


@pytest.mark.parametrize("reply", _malformed_authorizations())
def test_closed_authorization_contract_denies_malformed_shapes_before_callback_or_invoke(
    reply,
):
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    callbacks = []
    invoked = []
    policy = FakePolicy([reply])
    with provenance(prov):
        value, denied = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda result: callbacks.append(result) or "capability",
        )
    assert value is None
    assert denied.rule_id == "policy.malformed_reply"
    assert callbacks == [] and invoked == []
    assert [method for method, _ in policy.calls] == ["authorize"]


@pytest.mark.parametrize(
    ("prov", "action_digest"),
    [
        (DeskPilotProvenance("ui", None, TRACE_ID), ACTION_DIGEST),
        (DeskPilotProvenance("scheduler", "job:health", TRACE_ID), None),
    ],
)
def test_deny_uses_policy_decision_and_never_invokes(prov, action_digest):
    invoked = []
    policy = FakePolicy([authorization("deny", actionDigest=action_digest)])
    with provenance(prov):
        value, reply = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
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
    assert [method for method, _ in policy.calls] == ["authorize"]


@pytest.mark.parametrize("verdict", ["ask", "local_confirm"])
def test_local_confirmation_failure_and_remote_response_never_invoke(verdict):
    prov = (
        DeskPilotProvenance("ui", None, TRACE_ID)
        if verdict == "local_confirm"
        else DeskPilotProvenance("telegram", "telegram:42", TRACE_ID)
    )
    auth = authorization(verdict)
    callbacks = []
    invoked = []
    with provenance(prov):
        value, reply = guarded_tool_call(
            FakePolicy([auth]),
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda result: (
                callbacks.append(result) or result.get("confirmationCapability")
            ),
        )
    assert value is None and reply.rule_id == "policy.approval_denied"
    assert callbacks == [auth.result]
    assert invoked == []


@pytest.mark.parametrize("verdict", ["ask", "local_confirm"])
def test_ask_resumes_only_with_nonempty_supplied_local_capability(verdict):
    prov = (
        DeskPilotProvenance("ui", None, TRACE_ID)
        if verdict == "local_confirm"
        else DeskPilotProvenance("telegram", "telegram:42", TRACE_ID)
    )
    policy = FakePolicy([
        authorization(verdict),
        execution(),
    ])
    invoked = []
    with provenance(prov):
        value, _ = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True) or "done",
            lambda _: "local-capability",
        )
    assert value == "done" and invoked == [True]
    assert policy.calls[1][1]["confirmationCapability"] == "local-capability"


@pytest.mark.parametrize(
    "prov",
    [
        DeskPilotProvenance("telegram", "telegram:42", TRACE_ID),
        DeskPilotProvenance("signal", "signal:+27820000000", TRACE_ID),
        DeskPilotProvenance("scheduler", "job:health", TRACE_ID),
    ],
)
def test_local_confirm_is_denied_outside_ui_before_callback_or_execute(prov):
    callbacks = []
    invoked = []
    policy = FakePolicy([authorization("local_confirm")])
    with provenance(prov):
        value, reply = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda result: callbacks.append(result) or "local-capability",
        )
    assert value is None and reply.rule_id == "policy.approval_denied"
    assert callbacks == [] and invoked == []
    assert [method for method, _ in policy.calls] == ["authorize"]


@pytest.mark.parametrize("offset_seconds", [-1, 600])
def test_pending_authorization_rejects_invalid_expiry_before_callback(offset_seconds):
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    auth = authorization(
        "ask",
        expiresAt=(datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat(),
    )
    callbacks = []
    invoked = []
    policy = FakePolicy([auth])
    with provenance(prov):
        value, reply = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda result: callbacks.append(result) or "local-capability",
        )
    assert value is None and reply.rule_id == "policy.malformed_reply"
    assert callbacks == [] and invoked == []
    assert [method for method, _ in policy.calls] == ["authorize"]


@pytest.mark.parametrize("capability", [None, "", 7])
def test_missing_or_invalid_local_capability_denies(capability):
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    invoked = []
    with provenance(prov):
        value, _ = guarded_tool_call(
            FakePolicy([authorization("ask")]),
            AdmittedRequest(prov, ADMISSION_ID),
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
        execution(False),
    ],
)
def test_execute_requires_literal_true_before_invocation(grant):
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    invoked = []
    with provenance(prov):
        value, reply = guarded_tool_call(
            FakePolicy([authorization(), grant]),
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda _: None,
        )
    assert value is None and not reply.allowed and invoked == []


@pytest.mark.parametrize(
    "grant",
    [
        execution(extra=True),
        PolicyReply(
            {
                "execute": True,
                "consumptionID": None,
                "ruleID": "execute.ok",
                "reason": "ok",
            },
            "policy.ok",
            "ok",
        ),
        execution(True, consumptionID=""),
        execution(False, consumptionID=CONSUMPTION_ID),
        execution(True, consumptionID="not-a-uuid"),
        execution(True, consumptionID=CONSUMPTION_ID.upper()),
        execution(True, ruleID=""),
        execution(True, reason=""),
        PolicyReply(
            {
                "execute": 1,
                "consumptionID": CONSUMPTION_ID,
                "ruleID": "execute.ok",
                "reason": "ok",
            },
            "policy.ok",
            "ok",
        ),
    ],
)
def test_closed_execute_contract_denies_malformed_shapes_before_invocation(grant):
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    invoked = []
    with provenance(prov):
        value, reply = guarded_tool_call(
            FakePolicy([authorization(), grant]),
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: invoked.append(True),
            lambda _: None,
        )
    assert value is None and reply.rule_id == "policy.malformed_reply"
    assert invoked == []


@pytest.mark.parametrize("stage", ["authorize", "approval", "execute"])
@pytest.mark.parametrize("nested", [False, True])
def test_argument_mutation_at_any_policy_boundary_denies_before_invocation(
    stage, nested
):
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    arguments = {"value": 1, "nested": {"value": 1}}
    invoked = []

    def mutate():
        if nested:
            arguments["nested"]["value"] = 2
        else:
            arguments["value"] = 2

    def on_call(method, _params):
        if method == stage:
            mutate()

    verdict = "ask" if stage == "approval" else "allow"
    policy = FakePolicy([authorization(verdict), execution()], on_call=on_call)

    def approve(_result):
        mutate()
        return "local-capability"

    with provenance(prov):
        value, reply = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            arguments,
            lambda snapshot: invoked.append(snapshot),
            approve,
        )

    assert value is None and reply.rule_id == "policy.arguments_changed"
    assert invoked == []


def test_invocation_receives_fresh_copy_of_authorized_arguments():
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    arguments = {"nested": {"value": 1}}
    received = []

    def invoke(snapshot):
        received.append(snapshot)
        snapshot["nested"]["value"] = 2
        return "done"

    with provenance(prov):
        value, reply = guarded_tool_call(
            FakePolicy([authorization(), execution()]),
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            arguments,
            invoke,
            lambda _: None,
        )

    assert value == "done" and reply.allowed
    assert received == [{"nested": {"value": 2}}]
    assert arguments == {"nested": {"value": 1}}


def test_invoker_with_unsupported_signature_denies_before_policy_call():
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    policy = FakePolicy([])
    with provenance(prov):
        value, reply = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda _first, _second: None,
            lambda _: None,
        )
    assert value is None and reply.rule_id == "policy.invalid_invoker"
    assert policy.calls == []


def test_guard_rejects_noncanonical_admission_id_before_policy_call():
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    policy = FakePolicy([])
    with provenance(prov):
        value, reply = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID.upper()),
            "cua_click",
            {},
            lambda: pytest.fail("must not invoke"),
            lambda _: None,
        )
    assert value is None and reply.rule_id == "policy.invalid_admission"
    assert policy.calls == []


def test_approval_callback_cannot_rebind_validated_action_digest():
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    policy = FakePolicy([authorization("ask"), execution()])

    def approve(result):
        result["actionDigest"] = "sha256:" + "b" * 64
        return "local-capability"

    with provenance(prov):
        value, _ = guarded_tool_call(
            policy,
            AdmittedRequest(prov, ADMISSION_ID),
            "cua_click",
            {},
            lambda: "done",
            approve,
        )
    assert value == "done"
    assert policy.calls[1][1]["actionDigest"] == ACTION_DIGEST


def test_missing_current_provenance_denies_without_policy_or_invocation():
    prov = DeskPilotProvenance("ui", None, TRACE_ID)
    policy = FakePolicy([])
    invoked = []
    value, reply = guarded_tool_call(
        policy,
        AdmittedRequest(prov, ADMISSION_ID),
        "cua_click",
        {},
        lambda: invoked.append(True),
        lambda _: None,
    )
    assert value is None and reply.rule_id == "policy.provenance_denied"
    assert policy.calls == [] and invoked == []


def test_provenance_mismatch_unmapped_tool_and_bad_arguments_deny_without_policy():
    current = DeskPilotProvenance("ui", None, "trace-current")
    admitted = AdmittedRequest(
        DeskPilotProvenance("ui", None, "trace-other"), ADMISSION_ID
    )
    for tool_name, arguments in (("cua_click", {}), ("unknown", {}), ("cua_click", [])):
        policy = FakePolicy([])
        with provenance(current):
            value, reply = guarded_tool_call(
                policy,
                admitted
                if tool_name != "unknown"
                else AdmittedRequest(current, ADMISSION_ID),
                tool_name,
                arguments,
                lambda: pytest.fail("must not invoke"),
                lambda _: None,
            )
        assert value is None and reply.result is None and policy.calls == []
