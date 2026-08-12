import json
import os
import socket
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from deskpilot_hermes.validation import (
    nonempty_string,
    validate_bounded_future,
    validate_uuid,
)


_PROTOCOL = "deskpilot.policy"
_VERSION = 1
_MAX_FRAME = 262_144
_RESPONSE_BASE_FIELDS = {"protocol", "version", "requestID"}
_EXECUTE_FIELDS = {"execute", "consumptionID", "ruleID", "reason"}


@dataclass(frozen=True)
class PolicyReply:
    result: dict[str, Any] | None
    rule_id: str
    reason: str

    @property
    def allowed(self) -> bool:
        result = self.result
        if not isinstance(result, dict) or set(result) != _EXECUTE_FIELDS:
            return False
        if result["execute"] is not True:
            return False
        if not nonempty_string(result["ruleID"]) or not nonempty_string(
            result["reason"]
        ):
            return False
        try:
            validate_uuid(result["consumptionID"])
        except (TypeError, ValueError):
            return False
        return True


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
    keys = set(response)
    result_branch = _RESPONSE_BASE_FIELDS | {"result"}
    error_branch = _RESPONSE_BASE_FIELDS | {"error"}
    if keys != result_branch and keys != error_branch:
        raise ValueError("response must contain exactly one outcome branch")
    if response.get("protocol") != _PROTOCOL:
        raise ValueError("protocol mismatch")
    if type(response.get("version")) is not int or response["version"] != _VERSION:
        raise ValueError("version mismatch")
    if response.get("requestID") != request_id:
        raise ValueError("request mismatch")

    result = response.get("result")
    error = response.get("error")
    if result is None and error is None:
        raise ValueError("response outcome must be non-null")
    if result is not None and not isinstance(result, dict):
        raise ValueError("result must be an object")
    if error is not None and not isinstance(error, dict):
        raise ValueError("error must be an object")
    if error is not None and set(error) != {"ruleID", "reason"}:
        raise ValueError("error must be a closed object")
    return result, error


class ParentPolicyClient:
    def __init__(self, path: str | None = None, timeout: float = 0.75):
        self.path = path or os.environ.get("DESKPILOT_POLICY_SOCKET", "")
        self.timeout = timeout

    def _socket_path(self) -> Path | None:
        if not self.path or "://" in self.path:
            return None
        path = Path(self.path)
        return path if path.is_absolute() else None

    @staticmethod
    def _validate_private_ancestors(path: Path) -> None:
        boundary = Path(os.environ.get("HOME", "")) / ".deskpilot"
        try:
            path.relative_to(boundary)
        except ValueError:
            return
        current = path.parent
        while True:
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise PermissionError("private socket ancestor must be a directory")
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise PermissionError("private socket ancestor permissions invalid")
            if current == boundary:
                return
            if boundary not in current.parents:
                raise PermissionError("private socket ancestor escaped boundary")
            current = current.parent

    @classmethod
    def _validate_endpoint(cls, path: Path) -> os.stat_result:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
            raise PermissionError("policy endpoint must be a socket, not a symlink")
        if metadata.st_uid != os.geteuid():
            raise PermissionError("policy socket owner mismatch")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PermissionError("policy socket mode must be 0600")
        cls._validate_private_ancestors(path)
        return metadata

    def _connect(self) -> socket.socket:
        path = self._socket_path()
        if path is None:
            raise ValueError("absolute local policy socket required")
        before = self._validate_endpoint(path)
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer.settimeout(self.timeout)
            peer.connect(str(path))
            after = self._validate_endpoint(path)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise PermissionError("policy socket changed during connect")
            return peer
        except BaseException:
            peer.close()
            raise

    def call(self, method: str, params: dict[str, Any]) -> PolicyReply:
        if self._socket_path() is None:
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
            payload = (
                json.dumps(request, separators=(",", ":"), allow_nan=False).encode()
                + b"\n"
            )
            with self._connect() as peer:
                peer.sendall(payload)
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
            TypeError,
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
        if self._socket_path() is None:
            return None
        try:
            for value in (pending_id, route_id, session_id, permission_id):
                validate_uuid(value)
        except (TypeError, ValueError):
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
            with self._connect() as peer:
                peer.sendall(
                    json.dumps(request, separators=(",", ":")).encode() + b"\n"
                )
                with peer.makefile("rb") as stream:
                    acknowledgement = _read_stream_frame(stream)
                    result, error = _validate_response(acknowledgement, request_id)
                    if error is not None or result is None:
                        return None
                    if set(result) != {
                        "subscribed",
                        "pendingApprovalID",
                        "expiresAt",
                    }:
                        return None
                    if result.get("subscribed") is not True:
                        return None
                    if result.get("pendingApprovalID") != pending_id:
                        return None
                    validate_uuid(result.get("pendingApprovalID"))
                    expires = validate_bounded_future(result["expiresAt"])
                    remaining = (expires - datetime.now(UTC)).total_seconds()
                    peer.settimeout(remaining + 2.0)
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
            validate_uuid(event.get("eventID"))
            for field in (
                "pendingApprovalID",
                "routeID",
                "sessionID",
                "permissionRequestID",
            ):
                validate_uuid(event.get(field))
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
