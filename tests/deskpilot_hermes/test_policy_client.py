import json
import socket
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from deskpilot_hermes.policy import ParentPolicyClient, PolicyReply


MAX_FRAME = 262_144


def response_for(request, **outcome):
    return {
        "protocol": "deskpilot.policy",
        "version": 1,
        "requestID": request["requestID"],
        **outcome,
    }


@contextmanager
def unix_server(tmp_path, handler):
    path = tmp_path / "policy.sock"
    ready = threading.Event()
    errors = []

    def serve():
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                ready.set()
                connection, _ = listener.accept()
                with connection:
                    raw = bytearray()
                    while not raw.endswith(b"\n"):
                        block = connection.recv(4096)
                        if not block:
                            break
                        raw.extend(block)
                    handler(json.loads(raw), connection)
        except Exception as exc:  # surfaced in the test thread
            errors.append(exc)
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(2)
    try:
        yield str(path)
    finally:
        thread.join(3)
        assert not thread.is_alive()
        if errors:
            raise errors[0]


def send_frame(connection, frame):
    connection.sendall(json.dumps(frame, separators=(",", ":")).encode() + b"\n")


def test_policy_reply_allowed_requires_result_and_execute_not_false():
    assert PolicyReply({}, "policy.ok", "ok").allowed
    assert PolicyReply({"execute": True}, "policy.ok", "ok").allowed
    assert not PolicyReply({"execute": False}, "policy.ok", "ok").allowed
    assert not PolicyReply(None, "policy.denied", "no").allowed


def test_call_sends_exact_request_and_accepts_correlated_result(tmp_path):
    requests = []

    def handler(request, connection):
        requests.append(request)
        send_frame(connection, response_for(request, result={"admitted": True}))

    with unix_server(tmp_path, handler) as path:
        reply = ParentPolicyClient(path).call("admit", {"entryPoint": "ui"})

    assert reply == PolicyReply({"admitted": True}, "policy.ok", "authorized")
    assert requests[0].keys() == {
        "protocol",
        "version",
        "requestID",
        "method",
        "params",
    }
    assert requests[0]["protocol"] == "deskpilot.policy"
    assert type(requests[0]["version"]) is int and requests[0]["version"] == 1
    assert requests[0]["method"] == "admit"
    assert requests[0]["params"] == {"entryPoint": "ui"}
    assert requests[0]["requestID"]


def test_call_accepts_correlated_error(tmp_path):
    def handler(request, connection):
        send_frame(
            connection,
            response_for(
                request, error={"ruleID": "admit.denied", "reason": "not allowed"}
            ),
        )

    with unix_server(tmp_path, handler) as path:
        reply = ParentPolicyClient(path).call("admit", {})

    assert reply == PolicyReply(None, "admit.denied", "not allowed")


def test_call_rejects_extra_nested_error_fields(tmp_path):
    def handler(request, connection):
        send_frame(
            connection,
            response_for(
                request,
                error={
                    "ruleID": "admit.denied",
                    "reason": "not allowed",
                    "extra": True,
                },
            ),
        )

    with unix_server(tmp_path, handler) as path:
        reply = ParentPolicyClient(path).call("admit", {})

    assert reply.result is None and reply.rule_id == "policy.transport_denied"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda response: response.update(extra=True),
        lambda response: response.update(version=True),
        lambda response: response.update(requestID="other"),
        lambda response: response.update(error={"ruleID": "also", "reason": "double"}),
        lambda response: response.pop("result"),
        lambda response: response.update(protocol="other"),
        lambda response: response.update(result=[]),
    ],
)
def test_call_rejects_unexpected_or_malformed_response_shapes(tmp_path, mutate):
    def handler(request, connection):
        frame = response_for(request, result={"ok": True})
        mutate(frame)
        send_frame(connection, frame)

    with unix_server(tmp_path, handler) as path:
        reply = ParentPolicyClient(path).call("authorize", {})

    assert reply.result is None
    assert reply.rule_id == "policy.transport_denied"


@pytest.mark.parametrize("payload", [b"x" * (MAX_FRAME + 1) + b"\n", b"{}"])
def test_call_rejects_oversize_or_no_newline_response(tmp_path, payload):
    def handler(_request, connection):
        connection.sendall(payload)

    with unix_server(tmp_path, handler) as path:
        reply = ParentPolicyClient(path, timeout=0.1).call("authorize", {})

    assert reply.result is None
    assert reply.rule_id == "policy.transport_denied"


def test_missing_uri_and_socket_outage_fail_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("DESKPILOT_POLICY_SOCKET", raising=False)
    assert ParentPolicyClient().call("admit", {}).rule_id == "policy.socket_required"
    assert (
        ParentPolicyClient("http://localhost/policy").call("admit", {}).rule_id
        == "policy.socket_required"
    )
    reply = ParentPolicyClient(str(tmp_path / "missing.sock"), timeout=0.01).call(
        "admit", {}
    )
    assert reply.result is None and reply.rule_id == "policy.transport_denied"


def approval_ack(request):
    expires = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()
    return response_for(
        request,
        result={
            "subscribed": True,
            "pendingApprovalID": request["params"]["pendingApprovalID"],
            "expiresAt": expires,
        },
    )


def approval_event(request, resolution="approve", **changes):
    event = {
        "type": "approval.resolved",
        "eventID": "event-1",
        **request["params"],
        "resolution": resolution,
        "confirmationCapability": "local-capability",
    }
    event.update(changes)
    return {"protocol": "deskpilot.policy", "version": 1, "event": event}


def test_approval_subscribe_sends_exact_correlation_and_returns_only_approve(tmp_path):
    requests = []

    def handler(request, connection):
        requests.append(request)
        send_frame(connection, approval_ack(request))
        send_frame(connection, approval_event(request))

    with unix_server(tmp_path, handler) as path:
        event = ParentPolicyClient(path).subscribe_approval(
            "pending-1", "route-1", "session-1", "permission-1"
        )

    assert requests[0].keys() == {
        "protocol",
        "version",
        "requestID",
        "method",
        "params",
    }
    assert requests[0]["method"] == "approval.subscribe"
    assert requests[0]["params"] == {
        "pendingApprovalID": "pending-1",
        "routeID": "route-1",
        "sessionID": "session-1",
        "permissionRequestID": "permission-1",
    }
    assert event["resolution"] == "approve"
    assert event["confirmationCapability"] == "local-capability"


def test_approval_subscribe_rejects_extra_acknowledgement_result_fields(tmp_path):
    def handler(request, connection):
        acknowledgement = approval_ack(request)
        acknowledgement["result"]["extra"] = True
        send_frame(connection, acknowledgement)
        send_frame(connection, approval_event(request))

    with unix_server(tmp_path, handler) as path:
        event = ParentPolicyClient(path).subscribe_approval(
            "pending-1", "route-1", "session-1", "permission-1"
        )

    assert event is None


@pytest.mark.parametrize("expiry", ["past", "distant", "naive"])
def test_approval_subscribe_rejects_invalid_expiry_bounds(tmp_path, expiry):
    def handler(request, connection):
        acknowledgement = approval_ack(request)
        if expiry == "naive":
            expires_at = datetime.now() + timedelta(seconds=30)
        else:
            offset = -1 if expiry == "past" else 600
            expires_at = datetime.now(UTC) + timedelta(seconds=offset)
        acknowledgement["result"]["expiresAt"] = expires_at.isoformat()
        send_frame(connection, acknowledgement)
        send_frame(connection, approval_event(request))

    with unix_server(tmp_path, handler) as path:
        event = ParentPolicyClient(path).subscribe_approval(
            "pending-1", "route-1", "session-1", "permission-1"
        )

    assert event is None


@pytest.mark.parametrize(
    "mode", ["mismatch", "denial", "disconnect", "bad_ack", "malformed_event"]
)
def test_approval_mismatch_denial_disconnect_and_bad_ack_return_none(tmp_path, mode):
    def handler(request, connection):
        if mode == "bad_ack":
            ack = approval_ack(request)
            ack["requestID"] = "wrong"
            send_frame(connection, ack)
            return
        send_frame(connection, approval_ack(request))
        if mode == "disconnect":
            return
        if mode == "denial":
            send_frame(connection, approval_event(request, resolution="deny"))
        elif mode == "malformed_event":
            frame = approval_event(request)
            frame["event"]["confirmationCapability"] = None
            send_frame(connection, frame)
        else:
            send_frame(connection, approval_event(request, routeID="other"))

    with unix_server(tmp_path, handler) as path:
        event = ParentPolicyClient(path, timeout=0.1).subscribe_approval(
            "pending-1", "route-1", "session-1", "permission-1"
        )

    assert event is None
