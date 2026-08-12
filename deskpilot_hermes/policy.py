import json
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


_PROTOCOL = "deskpilot.policy"
_VERSION = 1
_MAX_FRAME = 262_144
_RESPONSE_FIELDS = {"protocol", "version", "requestID", "result", "error"}


@dataclass(frozen=True)
class PolicyReply:
    result: dict[str, Any] | None
    rule_id: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.result is not None and self.result.get("execute") is not False


def _read_frame(peer: socket.socket) -> dict[str, Any]:
    raw = bytearray()
    while not raw.endswith(b"\n"):
        block = peer.recv(min(4096, _MAX_FRAME + 1 - len(raw)))
        if not block:
            raise ValueError("response missing newline")
        raw.extend(block)
        if len(raw) > _MAX_FRAME:
            raise ValueError("response exceeds maximum frame size")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("response must be an object")
    return value


def _read_stream_frame(stream: Any) -> dict[str, Any]:
    raw = stream.readline(_MAX_FRAME + 1)
    if not raw.endswith(b"\n"):
        raise ValueError("response missing newline or exceeds maximum frame size")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("response must be an object")
    return value


def _validate_response(
    response: dict[str, Any], request_id: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not set(response).issubset(_RESPONSE_FIELDS):
        raise ValueError("unexpected response fields")
    if response.get("protocol") != _PROTOCOL:
        raise ValueError("protocol mismatch")
    if type(response.get("version")) is not int or response["version"] != _VERSION:
        raise ValueError("version mismatch")
    if response.get("requestID") != request_id:
        raise ValueError("request mismatch")

    result = response.get("result")
    error = response.get("error")
    if (result is None) == (error is None):
        raise ValueError("response must contain exactly one non-null outcome")
    if result is not None and not isinstance(result, dict):
        raise ValueError("result must be an object")
    if error is not None and not isinstance(error, dict):
        raise ValueError("error must be an object")
    return result, error


class ParentPolicyClient:
    def __init__(self, path: str | None = None, timeout: float = 0.75):
        self.path = path or os.environ.get("DESKPILOT_POLICY_SOCKET", "")
        self.timeout = timeout

    def call(self, method: str, params: dict[str, Any]) -> PolicyReply:
        if not self.path or "://" in self.path:
            return PolicyReply(
                None, "policy.socket_required", "Unix policy socket required"
            )
        request_id = str(uuid4())
        request = {
            "protocol": _PROTOCOL,
            "version": _VERSION,
            "requestID": request_id,
            "method": method,
            "params": params,
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(self.timeout)
                peer.connect(self.path)
                peer.sendall(
                    json.dumps(request, separators=(",", ":")).encode() + b"\n"
                )
                response = _read_frame(peer)
            result, error = _validate_response(response, request_id)
            if error is None:
                return PolicyReply(result, "policy.ok", "authorized")
            rule_id = error["ruleID"]
            reason = error["reason"]
            if not isinstance(rule_id, str) or not isinstance(reason, str):
                raise ValueError("error fields must be strings")
            return PolicyReply(None, rule_id, reason)
        except (
            OSError,
            TimeoutError,
            ValueError,
            KeyError,
            json.JSONDecodeError,
        ) as exc:
            return PolicyReply(None, "policy.transport_denied", type(exc).__name__)

    def subscribe_approval(
        self,
        pending_id: str,
        route_id: str,
        session_id: str,
        permission_id: str,
    ) -> dict[str, Any] | None:
        if not self.path or "://" in self.path:
            return None
        request_id = str(uuid4())
        params = {
            "pendingApprovalID": pending_id,
            "routeID": route_id,
            "sessionID": session_id,
            "permissionRequestID": permission_id,
        }
        request = {
            "protocol": _PROTOCOL,
            "version": _VERSION,
            "requestID": request_id,
            "method": "approval.subscribe",
            "params": params,
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(self.timeout)
                peer.connect(self.path)
                peer.sendall(
                    json.dumps(request, separators=(",", ":")).encode() + b"\n"
                )
                with peer.makefile("rb") as stream:
                    acknowledgement = _read_stream_frame(stream)
                    result, error = _validate_response(acknowledgement, request_id)
                    if error is not None or result is None:
                        return None
                    if result.get("subscribed") is not True:
                        return None
                    if result.get("pendingApprovalID") != pending_id:
                        return None
                    expires_at = result["expiresAt"]
                    if not isinstance(expires_at, str):
                        return None
                    expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if expires.tzinfo is None:
                        raise ValueError("expiry must include timezone")
                    remaining = max(0.0, (expires - datetime.now(UTC)).total_seconds())
                    peer.settimeout(min(300.0, remaining) + 2.0)
                    frame = _read_stream_frame(stream)

            if set(frame) != {"protocol", "version", "event"}:
                return None
            if frame.get("protocol") != _PROTOCOL:
                return None
            if type(frame.get("version")) is not int or frame["version"] != _VERSION:
                return None
            event = frame.get("event")
            if not isinstance(event, dict):
                return None
            required_event_fields = {
                "type",
                "eventID",
                "pendingApprovalID",
                "routeID",
                "sessionID",
                "permissionRequestID",
                "resolution",
                "confirmationCapability",
            }
            if set(event) != required_event_fields:
                return None
            if event.get("type") != "approval.resolved":
                return None
            actual = (
                event.get("pendingApprovalID"),
                event.get("routeID"),
                event.get("sessionID"),
                event.get("permissionRequestID"),
            )
            expected = (pending_id, route_id, session_id, permission_id)
            if actual != expected or event.get("resolution") != "approve":
                return None
            capability = event.get("confirmationCapability")
            if not isinstance(capability, str) or not capability:
                return None
            return event
        except (OSError, TimeoutError, ValueError, KeyError, json.JSONDecodeError):
            return None
