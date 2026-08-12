import json
import os
import socket
import tempfile
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from deskpilot_hermes.policy import ParentPolicyClient, PolicyReply


MAX_FRAME = 262_144
PENDING_ID = "74e96407-e06c-4784-825f-36315b0be447"
ROUTE_ID = "116771cc-df21-437a-b28d-5944a42c1a45"
SESSION_ID = "3616552d-1ab5-4565-822f-63fcedb82cab"
PERMISSION_ID = "b1d75631-5f89-4f4d-a8b0-2b8501bc9a1f"
EVENT_ID = "6d6fe658-0bd7-4086-9569-7e344cb3d285"
CONSUMPTION_ID = "d10f4f35-18b8-48e9-a146-4e70f82ea19b"


def response_for(request, **outcome):
    return {
        "protocol": "deskpilot.policy",
        "version": 1,
        "requestID": request["requestID"],
        **outcome,
    }


@contextmanager
def unix_server(tmp_path, handler, *, path=None, mode=0o600):
    path = Path(path) if path is not None else tmp_path / "policy.sock"
    ready = threading.Event()
    errors = []

    def serve():
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                os.chmod(path, mode)
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
                    if raw:
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


@contextmanager
def bound_socket(path, *, mode=0o600):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chmod(path, mode)
        listener.listen(1)
        yield str(path), listener


def assert_no_connection(listener):
    listener.settimeout(0.05)
    with pytest.raises(socket.timeout):
        listener.accept()


def send_frame(connection, frame):
    connection.sendall(json.dumps(frame, separators=(",", ":")).encode() + b"\n")


def test_policy_reply_allowed_requires_exact_successful_execute_result():
    successful = {
        "execute": True,
        "consumptionID": CONSUMPTION_ID,
        "ruleID": "execute.allowed",
        "reason": "authorized",
    }
    assert PolicyReply(successful, "policy.ok", "ok").allowed
    assert not PolicyReply({}, "policy.ok", "ok").allowed
    assert not PolicyReply({"execute": True}, "policy.ok", "ok").allowed
    assert not PolicyReply({**successful, "extra": True}, "policy.ok", "ok").allowed
    assert not PolicyReply(
        {**successful, "consumptionID": CONSUMPTION_ID.upper()},
        "policy.ok",
        "ok",
    ).allowed
    assert not PolicyReply({"execute": False}, "policy.ok", "ok").allowed
    assert not PolicyReply(None, "policy.denied", "no").allowed


@pytest.mark.parametrize(
    ("value", "exception_name"), [(object(), "TypeError"), (float("nan"), "ValueError")]
)
def test_call_rejects_non_json_values_as_transport_denial(
    tmp_path, value, exception_name
):
    reply = ParentPolicyClient(str(tmp_path / "missing.sock")).call(
        "authorize", {"value": value}
    )
    assert reply == PolicyReply(None, "policy.transport_denied", exception_name)


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


@pytest.mark.parametrize("branch", ["result_with_null_error", "error_with_null_result"])
def test_call_requires_exact_top_level_outcome_branch_keys(tmp_path, branch):
    def handler(request, connection):
        if branch == "result_with_null_error":
            frame = response_for(request, result={"ok": True}, error=None)
        else:
            frame = response_for(
                request,
                error={"ruleID": "admit.denied", "reason": "no"},
                result=None,
            )
        send_frame(connection, frame)

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


def test_relative_socket_path_is_rejected():
    assert ParentPolicyClient("relative.sock").call("admit", {}).rule_id == (
        "policy.socket_required"
    )


def test_regular_file_is_rejected_as_socket(tmp_path):
    path = tmp_path / "policy.sock"
    path.write_text("not a socket")
    path.chmod(0o600)
    assert ParentPolicyClient(str(path)).call("admit", {}).rule_id == (
        "policy.transport_denied"
    )


def test_symlink_socket_path_is_rejected(tmp_path):
    with bound_socket(tmp_path / "real.sock") as (real_path, listener):
        link = tmp_path / "policy.sock"
        link.symlink_to(real_path)
        assert ParentPolicyClient(str(link)).call("admit", {}).rule_id == (
            "policy.transport_denied"
        )
        assert_no_connection(listener)


def test_socket_with_wrong_mode_is_rejected(tmp_path):
    with bound_socket(tmp_path / "policy.sock", mode=0o660) as (path, listener):
        assert ParentPolicyClient(path).call("admit", {}).rule_id == (
            "policy.transport_denied"
        )
        assert_no_connection(listener)


def test_socket_with_wrong_owner_is_rejected(monkeypatch, tmp_path):
    with bound_socket(tmp_path / "policy.sock") as (path, listener):
        monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
        assert ParentPolicyClient(path).call("admit", {}).rule_id == (
            "policy.transport_denied"
        )
        assert_no_connection(listener)


def test_private_run_directory_permissions_are_required(monkeypatch, tmp_path):
    with tempfile.TemporaryDirectory(prefix="dph-", dir="/private/tmp") as directory:
        home = Path(directory)
        run = home / ".deskpilot" / "run"
        run.mkdir(parents=True)
        (home / ".deskpilot").chmod(0o700)
        run.chmod(0o750)
        monkeypatch.setenv("HOME", str(home))
        with bound_socket(run / "policy.sock") as (path, listener):
            assert ParentPolicyClient(path).call("admit", {}).rule_id == (
                "policy.transport_denied"
            )
            assert_no_connection(listener)


def test_socket_inode_swap_is_rejected(monkeypatch, tmp_path):
    def handler(request, connection):
        send_frame(connection, response_for(request, result={"ok": True}))

    with unix_server(tmp_path, handler) as path:
        socket_path = Path(path)
        original_lstat = Path.lstat
        calls = 0

        def swapped_lstat(self):
            nonlocal calls
            metadata = original_lstat(self)
            if self == socket_path:
                calls += 1
                if calls == 2:
                    values = list(metadata)
                    values[1] += 1
                    return os.stat_result(values)
            return metadata

        monkeypatch.setattr(Path, "lstat", swapped_lstat)
        reply = ParentPolicyClient(path).call("admit", {})

    assert reply.result is None and reply.rule_id == "policy.transport_denied"


def test_private_absolute_0600_socket_is_accepted(monkeypatch, tmp_path):
    with tempfile.TemporaryDirectory(prefix="dph-", dir="/private/tmp") as directory:
        home = Path(directory)
        run = home / ".deskpilot" / "run"
        run.mkdir(parents=True)
        (home / ".deskpilot").chmod(0o700)
        run.chmod(0o700)
        monkeypatch.setenv("HOME", str(home))

        def handler(request, connection):
            send_frame(connection, response_for(request, result={"ok": True}))

        with unix_server(tmp_path, handler, path=run / "policy.sock") as path:
            reply = ParentPolicyClient(path).call("admit", {})

    assert reply == PolicyReply({"ok": True}, "policy.ok", "authorized")


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
        "eventID": EVENT_ID,
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
            PENDING_ID, ROUTE_ID, SESSION_ID, PERMISSION_ID
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
        "pendingApprovalID": PENDING_ID,
        "routeID": ROUTE_ID,
        "sessionID": SESSION_ID,
        "permissionRequestID": PERMISSION_ID,
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
            PENDING_ID, ROUTE_ID, SESSION_ID, PERMISSION_ID
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
            PENDING_ID, ROUTE_ID, SESSION_ID, PERMISSION_ID
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
            PENDING_ID, ROUTE_ID, SESSION_ID, PERMISSION_ID
        )

    assert event is None


@pytest.mark.parametrize(
    "field",
    ["pendingApprovalID", "routeID", "sessionID", "permissionRequestID"],
)
@pytest.mark.parametrize("kind", ["malformed", "noncanonical"])
def test_approval_rejects_invalid_input_correlation_uuid_before_connect(
    monkeypatch, field, kind
):
    values = {
        "pendingApprovalID": PENDING_ID,
        "routeID": ROUTE_ID,
        "sessionID": SESSION_ID,
        "permissionRequestID": PERMISSION_ID,
    }
    values[field] = "not-a-uuid" if kind == "malformed" else values[field].upper()
    client = ParentPolicyClient("/private/tmp/policy.sock")
    monkeypatch.setattr(
        client, "_connect", lambda: pytest.fail("invalid UUID must not connect")
    )
    assert client.subscribe_approval(*values.values()) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eventID", "not-a-uuid"),
        ("eventID", EVENT_ID.upper()),
        ("pendingApprovalID", PENDING_ID.upper()),
        ("routeID", ROUTE_ID.upper()),
        ("sessionID", SESSION_ID.upper()),
        ("permissionRequestID", PERMISSION_ID.upper()),
    ],
)
def test_approval_rejects_malformed_or_noncanonical_event_uuid(tmp_path, field, value):
    def handler(request, connection):
        send_frame(connection, approval_ack(request))
        send_frame(connection, approval_event(request, **{field: value}))

    with unix_server(tmp_path, handler) as path:
        event = ParentPolicyClient(path).subscribe_approval(
            PENDING_ID, ROUTE_ID, SESSION_ID, PERMISSION_ID
        )
    assert event is None


def test_approval_rejects_non_rfc3339_acknowledgement_timestamp(tmp_path):
    def handler(request, connection):
        acknowledgement = approval_ack(request)
        acknowledgement["result"]["expiresAt"] = (
            (datetime.now(UTC) + timedelta(seconds=30)).isoformat().replace("T", " ")
        )
        send_frame(connection, acknowledgement)
        send_frame(connection, approval_event(request))

    with unix_server(tmp_path, handler) as path:
        event = ParentPolicyClient(path).subscribe_approval(
            PENDING_ID, ROUTE_ID, SESSION_ID, PERMISSION_ID
        )
    assert event is None
