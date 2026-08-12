from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

from deskpilot_hermes.integration import AdmittedRequest
from deskpilot_hermes.provenance import (
    DeskPilotProvenance,
    provenance,
    require_provenance,
)
from deskpilot_hermes.runtime_context import (
    PermissionOutcome,
    require_admitted_request,
    require_permission_requester,
    require_tool_dispatcher,
    require_trusted_user_request,
    reset_admitted_request,
    reset_permission_requester,
    reset_tool_dispatcher,
    reset_trusted_user_request,
    set_admitted_request,
    set_permission_requester,
    set_tool_dispatcher,
    set_trusted_user_request,
    wait_for_local_approval,
)


PENDING_ID = "74e96407-e06c-4784-825f-36315b0be447"
EVENT_ID = "d10f4f35-18b8-48e9-a146-4e70f82ea19b"


def authorization(**changes):
    value = {
        "decision": {
            "risk": "mutation",
            "verdict": "ask",
            "ruleID": "decision.ask",
            "reason": "approval required",
        },
        "actionDigest": "sha256:" + "a" * 64,
        "pendingApprovalID": PENDING_ID,
        "expiresAt": (datetime.now(UTC) + timedelta(seconds=60)).isoformat(),
    }
    value.update(changes)
    return value


class Pending:
    def __init__(self, route_id, *, emitted=True, outcome=True):
        self.route_id = route_id
        self.session_id = "session-1"
        self.permission_request_id = "permission-1"
        self.emitted = emitted
        self.outcome = outcome
        self.calls = []

    def wait_emitted(self, timeout_seconds):
        self.calls.append(("wait_emitted", timeout_seconds))
        return self.emitted

    def wait(self, expires_at):
        self.calls.append(("wait", expires_at))
        if self.outcome is None:
            return None
        return PermissionOutcome(
            route_id=self.route_id,
            session_id=self.session_id,
            permission_request_id=self.permission_request_id,
            approved=self.outcome,
        )


class ApprovalPolicy:
    def __init__(self, event_factory=None, *, raises=False):
        self.event_factory = event_factory or self._approved_event
        self.raises = raises
        self.calls = []

    @staticmethod
    def _approved_event(pending_id, route_id, session_id, permission_id):
        return {
            "type": "approval.resolved",
            "eventID": EVENT_ID,
            "pendingApprovalID": pending_id,
            "routeID": route_id,
            "sessionID": session_id,
            "permissionRequestID": permission_id,
            "resolution": "approve",
            "confirmationCapability": "capability-1",
        }

    def subscribe_approval(self, pending_id, route_id, session_id, permission_id):
        self.calls.append((pending_id, route_id, session_id, permission_id))
        if self.raises:
            raise ConnectionError("disconnected")
        return self.event_factory(pending_id, route_id, session_id, permission_id)


def _with_requester(requester):
    token = set_permission_requester(requester)
    return token


def test_context_values_are_required_and_tokens_restore_prior_values():
    for require in (
        require_admitted_request,
        require_permission_requester,
        require_trusted_user_request,
        require_tool_dispatcher,
    ):
        with pytest.raises(PermissionError):
            require()

    admitted = AdmittedRequest(
        DeskPilotProvenance("ui", None, "b4783542-8cc5-4b03-a43f-239445405eed"),
        "a399f2e8-c425-49d7-9f90-67d46c436aa0",
    )
    requester = object()
    dispatcher = object()
    admitted_token = set_admitted_request(admitted)
    requester_token = set_permission_requester(requester)
    request_token = set_trusted_user_request("open the browser")
    dispatcher_token = set_tool_dispatcher(dispatcher)
    try:
        assert require_admitted_request() is admitted
        assert require_permission_requester() is requester
        assert require_trusted_user_request() == "open the browser"
        assert require_tool_dispatcher() is dispatcher
    finally:
        reset_tool_dispatcher(dispatcher_token)
        reset_trusted_user_request(request_token)
        reset_permission_requester(requester_token)
        reset_admitted_request(admitted_token)


def test_copied_concurrent_contexts_keep_all_session_values_isolated():
    barrier = Barrier(2)

    def make_session(index):
        trace_id = f"00000000-0000-0000-0000-{index:012d}"
        admission_id = f"10000000-0000-0000-0000-{index:012d}"
        admitted = AdmittedRequest(
            DeskPilotProvenance("ui", f"local:{index}", trace_id), admission_id
        )
        requester = object()
        dispatcher = object()
        admitted_token = set_admitted_request(admitted)
        requester_token = set_permission_requester(requester)
        request_token = set_trusted_user_request(f"request-{index}")
        dispatcher_token = set_tool_dispatcher(dispatcher)
        try:
            with provenance(admitted.provenance):
                context = copy_context()
        finally:
            reset_tool_dispatcher(dispatcher_token)
            reset_trusted_user_request(request_token)
            reset_permission_requester(requester_token)
            reset_admitted_request(admitted_token)

        def observe():
            barrier.wait()
            return (
                require_admitted_request(),
                require_permission_requester(),
                require_trusted_user_request(),
                require_tool_dispatcher(),
                require_provenance(),
            )

        return context, observe, admitted, requester, dispatcher

    sessions = [make_session(1), make_session(2)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(context.run, observe)
            for context, observe, *_expected in sessions
        ]
        observed = [future.result() for future in futures]

    for values, (_, _, admitted, requester, dispatcher) in zip(observed, sessions):
        assert values == (
            admitted,
            requester,
            f"request-{admitted.provenance.sender.removeprefix('local:')}",
            dispatcher,
            admitted.provenance,
        )


@pytest.mark.parametrize("value", [None, "", 0, [], {}])
def test_trusted_user_request_rejects_empty_or_non_string(value):
    with pytest.raises((TypeError, ValueError)):
        set_trusted_user_request(value)


def test_missing_or_raising_requester_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "deskpilot_hermes.runtime_context.ParentPolicyClient", ApprovalPolicy
    )
    assert wait_for_local_approval(authorization()) is None

    token = _with_requester(lambda _request: (_ for _ in ()).throw(RuntimeError()))
    try:
        assert wait_for_local_approval(authorization()) is None
    finally:
        reset_permission_requester(token)


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        {},
        authorization(extra=True),
        authorization(pendingApprovalID=PENDING_ID.upper()),
        authorization(expiresAt="2099-08-12T12:00:00+00:00"),
        authorization(expiresAt=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()),
    ],
)
def test_malformed_authorization_is_rejected_before_requester(monkeypatch, malformed):
    called = []
    token = _with_requester(lambda request: called.append(request))
    monkeypatch.setattr(
        "deskpilot_hermes.runtime_context.ParentPolicyClient", ApprovalPolicy
    )
    try:
        assert wait_for_local_approval(malformed) is None
    finally:
        reset_permission_requester(token)
    assert called == []


@pytest.mark.parametrize("emitted", [False, None, 1])
def test_permission_emission_must_be_exact_true_before_subscribe(monkeypatch, emitted):
    policy = ApprovalPolicy()
    monkeypatch.setattr(
        "deskpilot_hermes.runtime_context.ParentPolicyClient", lambda: policy
    )
    pending_holder = []

    def requester(request):
        pending = Pending(request["routeID"], emitted=emitted)
        pending_holder.append(pending)
        return pending

    token = _with_requester(requester)
    try:
        assert wait_for_local_approval(authorization()) is None
    finally:
        reset_permission_requester(token)
    assert policy.calls == []
    assert pending_holder[0].calls == [("wait_emitted", 5.0)]


@pytest.mark.parametrize(
    "change",
    [
        {"route_id": "not-a-uuid"},
        {"route_id": "00000000-0000-0000-0000-000000000000"},
        {"session_id": ""},
        {"permission_request_id": ""},
    ],
)
def test_pending_correlation_mismatch_is_rejected_before_subscribe(monkeypatch, change):
    policy = ApprovalPolicy()
    monkeypatch.setattr(
        "deskpilot_hermes.runtime_context.ParentPolicyClient", lambda: policy
    )

    def requester(request):
        pending = Pending(request["routeID"])
        for name, value in change.items():
            setattr(pending, name, value)
        return pending

    token = _with_requester(requester)
    try:
        assert wait_for_local_approval(authorization()) is None
    finally:
        reset_permission_requester(token)
    assert policy.calls == []


def test_subscribe_disconnect_or_remote_outcome_without_event_fails_closed(monkeypatch):
    for policy in (ApprovalPolicy(raises=True), ApprovalPolicy(lambda *_: None)):
        monkeypatch.setattr(
            "deskpilot_hermes.runtime_context.ParentPolicyClient", lambda: policy
        )
        token = _with_requester(lambda request: Pending(request["routeID"]))
        try:
            assert wait_for_local_approval(authorization()) is None
        finally:
            reset_permission_requester(token)


@pytest.mark.parametrize("outcome", [None, False])
def test_parent_event_without_approved_ui_outcome_fails_closed(monkeypatch, outcome):
    policy = ApprovalPolicy()
    monkeypatch.setattr(
        "deskpilot_hermes.runtime_context.ParentPolicyClient", lambda: policy
    )
    token = _with_requester(
        lambda request: Pending(request["routeID"], outcome=outcome)
    )
    try:
        assert wait_for_local_approval(authorization()) is None
    finally:
        reset_permission_requester(token)


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("outcome", "route_id", "00000000-0000-0000-0000-000000000000"),
        ("outcome", "session_id", "other-session"),
        ("outcome", "permission_request_id", "other-permission"),
        ("event", "pendingApprovalID", "00000000-0000-0000-0000-000000000000"),
        ("event", "routeID", "00000000-0000-0000-0000-000000000000"),
        ("event", "sessionID", "other-session"),
        ("event", "permissionRequestID", "other-permission"),
        ("event", "resolution", "deny"),
        ("event", "resolution", "cancel"),
        ("event", "confirmationCapability", ""),
    ],
)
def test_outcome_and_parent_event_mismatches_fail_closed(
    monkeypatch, target, field, value
):
    pending_holder = []

    def requester(request):
        pending = Pending(request["routeID"])
        pending_holder.append(pending)
        return pending

    def event_factory(pending_id, route_id, session_id, permission_id):
        event = ApprovalPolicy._approved_event(
            pending_id, route_id, session_id, permission_id
        )
        if target == "event":
            event[field] = value
        return event

    policy = ApprovalPolicy(event_factory)
    monkeypatch.setattr(
        "deskpilot_hermes.runtime_context.ParentPolicyClient", lambda: policy
    )
    token = _with_requester(requester)
    try:
        if target == "outcome":
            original_wait = pending_holder

            def requester_with_changed_outcome(request):
                pending = Pending(request["routeID"])

                def wait(expires_at):
                    result = PermissionOutcome(
                        pending.route_id,
                        pending.session_id,
                        pending.permission_request_id,
                        True,
                    )
                    return PermissionOutcome(**{**result.__dict__, field: value})

                pending.wait = wait
                original_wait.append(pending)
                return pending

            reset_permission_requester(token)
            token = _with_requester(requester_with_changed_outcome)
        assert wait_for_local_approval(authorization()) is None
    finally:
        reset_permission_requester(token)


def test_exact_approval_success_consumes_each_source_once(monkeypatch):
    events = []
    policy = ApprovalPolicy()
    monkeypatch.setattr(
        "deskpilot_hermes.runtime_context.ParentPolicyClient", lambda: policy
    )

    def requester(request):
        events.append(("request", request))
        pending = Pending(request["routeID"])
        events.append(("pending", pending))
        return pending

    token = _with_requester(requester)
    try:
        capability = wait_for_local_approval(authorization())
    finally:
        reset_permission_requester(token)

    assert capability == "capability-1"
    request = events[0][1]
    pending = events[1][1]
    assert set(request) == {"routeID", "pendingApprovalID", "decision"}
    assert request["pendingApprovalID"] == PENDING_ID
    assert request["decision"] == authorization()["decision"]
    assert pending.calls[0] == ("wait_emitted", 5.0)
    assert pending.calls[1][0] == "wait"
    assert isinstance(pending.calls[1][1], datetime)
    assert len(pending.calls) == 2
    assert policy.calls == [
        (PENDING_ID, request["routeID"], "session-1", "permission-1")
    ]
