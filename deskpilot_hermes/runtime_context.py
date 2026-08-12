from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Protocol
from uuid import uuid4

from deskpilot_hermes.integration import (
    AdmittedRequest,
    _validate_authorization_result,
)
from deskpilot_hermes.policy import ParentPolicyClient
from deskpilot_hermes.validation import (
    nonempty_string,
    validate_bounded_future,
    validate_uuid,
)


@dataclass(frozen=True)
class PermissionOutcome:
    route_id: str
    session_id: str
    permission_request_id: str
    approved: bool


class PendingPermission(Protocol):
    route_id: str
    session_id: str
    permission_request_id: str

    def wait_emitted(self, timeout_seconds: float) -> bool: ...

    def wait(self, expires_at: datetime) -> PermissionOutcome | None: ...


PermissionRequester = Callable[[dict[str, Any]], PendingPermission]

_admitted_request: ContextVar[AdmittedRequest | None] = ContextVar(
    "deskpilot_admitted_request", default=None
)
_permission_requester: ContextVar[PermissionRequester | None] = ContextVar(
    "deskpilot_permission_requester", default=None
)
_trusted_user_request: ContextVar[str | None] = ContextVar(
    "deskpilot_trusted_user_request", default=None
)
_tool_dispatcher: ContextVar[Any | None] = ContextVar(
    "deskpilot_tool_dispatcher", default=None
)


def set_admitted_request(value: AdmittedRequest) -> Token[AdmittedRequest | None]:
    return _admitted_request.set(value)


def reset_admitted_request(token: Token[AdmittedRequest | None]) -> None:
    _admitted_request.reset(token)


def require_admitted_request() -> AdmittedRequest:
    value = _admitted_request.get()
    if value is None:
        raise PermissionError("DeskPilot admitted request missing")
    return value


def set_permission_requester(
    value: PermissionRequester,
) -> Token[PermissionRequester | None]:
    return _permission_requester.set(value)


def reset_permission_requester(token: Token[PermissionRequester | None]) -> None:
    _permission_requester.reset(token)


def require_permission_requester() -> PermissionRequester:
    value = _permission_requester.get()
    if value is None:
        raise PermissionError("DeskPilot permission requester missing")
    return value


def set_trusted_user_request(value: str) -> Token[str | None]:
    if not isinstance(value, str):
        raise TypeError("trusted user request must be a string")
    if not value:
        raise ValueError("trusted user request must not be empty")
    return _trusted_user_request.set(value)


def reset_trusted_user_request(token: Token[str | None]) -> None:
    _trusted_user_request.reset(token)


def require_trusted_user_request() -> str:
    value = _trusted_user_request.get()
    if value is None:
        raise PermissionError("DeskPilot trusted user request missing")
    return value


def set_tool_dispatcher(value: Any) -> Token[Any | None]:
    return _tool_dispatcher.set(value)


def reset_tool_dispatcher(token: Token[Any | None]) -> None:
    _tool_dispatcher.reset(token)


def require_tool_dispatcher() -> Any:
    value = _tool_dispatcher.get()
    if value is None:
        raise PermissionError("DeskPilot tool dispatcher missing")
    return value


def _validate_pending(
    pending: PendingPermission, expected_route_id: str
) -> tuple[str, str, str]:
    route_id = pending.route_id
    session_id = pending.session_id
    permission_id = pending.permission_request_id
    validate_uuid(route_id)
    if route_id != expected_route_id:
        raise ValueError("permission route mismatch")
    if not nonempty_string(session_id) or not nonempty_string(permission_id):
        raise ValueError("permission correlation missing")
    return route_id, session_id, permission_id


def _validate_event(event: Any, expected: tuple[str, str, str, str]) -> str:
    fields = {
        "type",
        "eventID",
        "pendingApprovalID",
        "routeID",
        "sessionID",
        "permissionRequestID",
        "resolution",
        "confirmationCapability",
    }
    if not isinstance(event, dict) or set(event) != fields:
        raise ValueError("approval event shape")
    if event["type"] != "approval.resolved":
        raise ValueError("approval event type")
    validate_uuid(event["eventID"])
    validate_uuid(event["pendingApprovalID"])
    validate_uuid(event["routeID"])
    if not nonempty_string(event["sessionID"]) or not nonempty_string(
        event["permissionRequestID"]
    ):
        raise ValueError("approval event correlation missing")
    actual = (
        event["pendingApprovalID"],
        event["routeID"],
        event["sessionID"],
        event["permissionRequestID"],
    )
    if actual != expected or event["resolution"] != "approve":
        raise ValueError("approval event mismatch")
    capability = event["confirmationCapability"]
    if not nonempty_string(capability):
        raise ValueError("approval capability missing")
    return capability


def wait_for_local_approval(authorization: Any) -> str | None:
    try:
        decision, verdict = _validate_authorization_result(authorization)
        if verdict not in {"ask", "local_confirm"}:
            return None
        requester = require_permission_requester()
        pending_id = authorization["pendingApprovalID"]
        expires_at = authorization["expiresAt"]
        expiry = validate_bounded_future(expires_at)
        route_id = str(uuid4())
        pending = requester({
            "routeID": route_id,
            "pendingApprovalID": pending_id,
            "decision": dict(decision),
            "expiresAt": expires_at,
        })
        route_id, session_id, permission_id = _validate_pending(pending, route_id)
        if pending.wait_emitted(5.0) is not True:
            return None
        event = ParentPolicyClient().subscribe_approval(
            pending_id, route_id, session_id, permission_id
        )
        if event is None:
            return None
        outcome = pending.wait(expiry)
        if type(outcome) is not PermissionOutcome or outcome.approved is not True:
            return None
        expected_outcome = (route_id, session_id, permission_id)
        actual_outcome = (
            outcome.route_id,
            outcome.session_id,
            outcome.permission_request_id,
        )
        if actual_outcome != expected_outcome:
            return None
        capability = _validate_event(
            event, (pending_id, route_id, session_id, permission_id)
        )
        if datetime.now(UTC) >= expiry:
            return None
        return capability
    except Exception:
        return None
