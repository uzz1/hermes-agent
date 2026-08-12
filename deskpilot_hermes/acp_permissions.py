import asyncio
import copy
import threading
import time
from concurrent.futures import Future, TimeoutError as FutureTimeout
from datetime import UTC, datetime
from typing import Any, Callable
from uuid import uuid4

import acp
from acp.connection import StreamDirection, StreamEvent
from acp.schema import AllowedOutcome, PermissionOption

from deskpilot_hermes.runtime_context import PermissionOutcome


class ACPEmissionTracker:
    """Bind ACP permission futures to requests observed after transport send."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, ACPPendingPermission] = {}
        self._recent_rpc_ids: list[int] = []

    @property
    def last_rpc_id(self) -> int | None:
        with self._lock:
            return self._recent_rpc_ids[-1] if self._recent_rpc_ids else None

    def register(self, pending: "ACPPendingPermission") -> None:
        with self._lock:
            if pending.permission_request_id in self._pending:
                raise RuntimeError("duplicate ACP permission correlation")
            self._pending[pending.permission_request_id] = pending

    def discard(self, pending: "ACPPendingPermission") -> None:
        with self._lock:
            if self._pending.get(pending.permission_request_id) is pending:
                self._pending.pop(pending.permission_request_id, None)

    def cancel_session(self, session_id: str) -> None:
        with self._lock:
            pending = [
                item for item in self._pending.values() if item.session_id == session_id
            ]
        for item in pending:
            item.cancel()

    def observe(self, event: StreamEvent) -> None:
        if event.direction is not StreamDirection.OUTGOING:
            return
        message = event.message
        if (
            not isinstance(message, dict)
            or message.get("method") != "session/request_permission"
        ):
            return
        params = message.get("params")
        metadata = params.get("_meta") if isinstance(params, dict) else None
        deskpilot = metadata.get("deskpilot") if isinstance(metadata, dict) else None
        if not isinstance(deskpilot, dict) or set(deskpilot) != {
            "routeID",
            "sessionID",
            "permissionRequestID",
            "pendingApprovalID",
            "expiresAt",
        }:
            return
        permission_id = deskpilot.get("permissionRequestID")
        with self._lock:
            pending = self._pending.get(permission_id)
        if pending is None or not pending.matches(deskpilot):
            return
        rpc_id = message.get("id")
        if type(rpc_id) is not int or rpc_id < 0:
            return
        if pending.mark_emitted(rpc_id):
            with self._lock:
                self._recent_rpc_ids.append(rpc_id)
                del self._recent_rpc_ids[:-256]


class ACPPendingPermission:
    def __init__(
        self,
        *,
        route_id: str,
        session_id: str,
        permission_request_id: str,
        pending_approval_id: str,
        expires_at: str,
        tracker: ACPEmissionTracker,
    ) -> None:
        self.route_id = route_id
        self.session_id = session_id
        self.permission_request_id = permission_request_id
        self.pending_approval_id = pending_approval_id
        self.expires_at = expires_at
        self.rpc_id: int | None = None
        self._tracker = tracker
        self._emitted = threading.Event()
        self._future: Future[Any] | None = None
        self._lock = threading.Lock()
        self._cancelled = False

    def attach(self, future: Future[Any]) -> None:
        with self._lock:
            if self._future is not None:
                raise RuntimeError("ACP permission future already attached")
            self._future = future

    def matches(self, metadata: dict[str, Any]) -> bool:
        return metadata == {
            "routeID": self.route_id,
            "sessionID": self.session_id,
            "permissionRequestID": self.permission_request_id,
            "pendingApprovalID": self.pending_approval_id,
            "expiresAt": self.expires_at,
        }

    def mark_emitted(self, rpc_id: int) -> bool:
        with self._lock:
            if self.rpc_id is not None or self._cancelled:
                return False
            self.rpc_id = rpc_id
            self._emitted.set()
            return True

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            future = self._future
            self._emitted.set()
        if future is not None:
            future.cancel()
        self._tracker.discard(self)

    def wait_emitted(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            if self._emitted.wait(min(0.05, max(0.0, deadline - time.monotonic()))):
                return self.rpc_id is not None and not self._cancelled
            future = self._future
            if future is not None and future.done():
                self._tracker.discard(self)
                return False
            if time.monotonic() >= deadline:
                if future is not None:
                    future.cancel()
                self._tracker.discard(self)
                return False

    def wait(self, expires_at: datetime) -> PermissionOutcome | None:
        future = self._future
        if future is None or self.rpc_id is None or self._cancelled:
            self._tracker.discard(self)
            return None
        timeout = max(0.0, (expires_at - datetime.now(UTC)).total_seconds())
        try:
            response = future.result(timeout=timeout)
        except (FutureTimeout, Exception):
            future.cancel()
            return None
        finally:
            self._tracker.discard(self)
        outcome = getattr(response, "outcome", None)
        approved = not self._cancelled and (
            isinstance(outcome, AllowedOutcome) and outcome.option_id == "allow_once"
        )
        return PermissionOutcome(
            self.route_id,
            self.session_id,
            self.permission_request_id,
            approved,
        )


class ACPPermissionBridge:
    def __init__(self) -> None:
        self.tracker = ACPEmissionTracker()
        self._connections: list[Any] = []

    @property
    def last_rpc_id(self) -> int | None:
        return self.tracker.last_rpc_id

    def connect(self, client: Any) -> None:
        connection = getattr(client, "_conn", None)
        if connection is None or not callable(
            getattr(connection, "add_observer", None)
        ):
            raise RuntimeError("ACP outgoing observer unavailable")
        if not any(item is connection for item in self._connections):
            connection.add_observer(self.tracker.observe)
            self._connections.append(connection)
            del self._connections[:-16]

    def requester(
        self,
        client: Any,
        loop: asyncio.AbstractEventLoop,
        session_id: str,
    ) -> Callable[[dict[str, Any]], ACPPendingPermission]:
        def request(authorization: dict[str, Any]) -> ACPPendingPermission:
            route_id = authorization.get("routeID")
            pending_id = authorization.get("pendingApprovalID")
            decision = authorization.get("decision")
            expires_at = authorization.get("expiresAt")
            if not isinstance(route_id, str) or not isinstance(pending_id, str):
                raise ValueError("ACP permission correlation missing")
            if not isinstance(decision, dict):
                raise ValueError("ACP permission decision missing")
            if not isinstance(expires_at, str) or not expires_at:
                raise ValueError("ACP permission expiry missing")
            permission_id = str(uuid4())
            pending = ACPPendingPermission(
                route_id=route_id,
                session_id=session_id,
                permission_request_id=permission_id,
                pending_approval_id=pending_id,
                expires_at=expires_at,
                tracker=self.tracker,
            )
            self.tracker.register(pending)
            metadata = {
                "routeID": route_id,
                "sessionID": session_id,
                "permissionRequestID": permission_id,
                "pendingApprovalID": pending_id,
                "expiresAt": expires_at,
            }
            tool_call = acp.update_tool_call(
                f"deskpilot-permission-{permission_id}",
                title="DeskPilot approval required",
                kind="execute",
                status="pending",
                raw_input={
                    "pendingApprovalID": pending_id,
                    "decision": copy.deepcopy(decision),
                },
            )
            options = [
                PermissionOption(
                    option_id="allow_once", kind="allow_once", name="Allow once"
                ),
                PermissionOption(option_id="deny", kind="reject_once", name="Deny"),
            ]
            try:
                future = asyncio.run_coroutine_threadsafe(
                    client.request_permission(
                        session_id=session_id,
                        tool_call=tool_call,
                        options=options,
                        deskpilot=metadata,
                    ),
                    loop,
                )
                pending.attach(future)
            except Exception:
                self.tracker.discard(pending)
                raise
            return pending

        return request

    def cancel_session(self, session_id: str) -> None:
        self.tracker.cancel_session(session_id)
