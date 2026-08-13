"""The sole Hermes component-status socket.

Runs as its own local process. Only the current UID may publish, readiness
expires after 15 seconds so a wedged component cannot look healthy forever, and
a disabled component reports distinctly from an unavailable one.
"""

import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

SOCKET_PATH = Path.home() / ".deskpilot/run/hermes-status.sock"
COMPONENTS = {"gateway", "cua"}
READY_TTL_SECONDS = 15.0
HEARTBEAT_INTERVAL_SECONDS = 10.0
MAX_FRAME = 65_536


def _peer_uid(peer: socket.socket) -> int:
    """Return the connecting process's UID.

    Mirrors the parent policy server's ladder. macOS CPython exposes neither
    ``getpeereid`` nor ``SO_PEERCRED``, only ``LOCAL_PEERCRED``, whose
    ``struct xucred`` carries the UID in its second field.
    """
    if hasattr(peer, "getpeereid"):
        return peer.getpeereid()[0]
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    if sys.platform == "darwin" and hasattr(socket, "LOCAL_PEERCRED"):
        return struct.unpack("3i", peer.getsockopt(0, socket.LOCAL_PEERCRED, 12))[1]
    raise PermissionError("peer credentials unavailable")


class StatusStore:
    """In-memory component readiness with an expiry on freshness."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        now = clock()
        self.values = {
            name: {"enabled": False, "ready": False, "updatedAt": now} for name in COMPONENTS
        }

    def publish(self, name: str, enabled: bool, ready: bool) -> None:
        if name not in COMPONENTS or not isinstance(enabled, bool) or not isinstance(ready, bool):
            raise ValueError("invalid status")
        self.values[name] = {"enabled": enabled, "ready": ready, "updatedAt": self.clock()}

    def read(self, name: str) -> dict[str, Any]:
        if name not in COMPONENTS:
            raise ValueError("invalid component")
        value = dict(self.values[name])
        value["stale"] = self.clock() - value.pop("updatedAt") > READY_TTL_SECONDS
        if value["stale"]:
            value["ready"] = False
        return value


class HermesStatusServer:
    def __init__(self, path: str | Path = SOCKET_PATH, store: StatusStore | None = None):
        self.path = Path(path)
        self.store = store or StatusStore()

    def dispatch(self, request: Any) -> dict[str, Any]:
        if set(request) != {"method", "params"} or not isinstance(request["params"], dict):
            raise ValueError("invalid request")
        method, params = request["method"], request["params"]
        if method == "status.publish":
            if set(params) != {"component", "enabled", "ready"}:
                raise ValueError("invalid publish")
            self.store.publish(params["component"], params["enabled"], params["ready"])
            return {"published": True}
        if method in {"gateway.status", "cua.status"} and params == {}:
            return self.store.read(method.split(".")[0])
        raise ValueError("unknown method")

    def serve(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self.path.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            listener.listen(8)
            while True:
                connection, _ = listener.accept()
                with connection:
                    try:
                        if _peer_uid(connection) != os.geteuid():
                            continue
                    except (OSError, PermissionError, struct.error):
                        continue
                    line = connection.makefile("rb").readline(MAX_FRAME + 1)
                    if len(line) > MAX_FRAME or not line.endswith(b"\n"):
                        continue
                    try:
                        response = {"result": self.dispatch(json.loads(line))}
                    except Exception as error:
                        response = {"error": type(error).__name__}
                    connection.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")


def _call(method: str, params: dict[str, Any]) -> Any:
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(1)
        peer.connect(str(SOCKET_PATH))
        peer.sendall(json.dumps({"method": method, "params": params}).encode() + b"\n")
        reply = json.loads(peer.makefile("rb").readline(MAX_FRAME + 1))
    if set(reply) != {"result"}:
        raise RuntimeError("Hermes status denied")
    return reply["result"]


def publish_status(component: str, enabled: bool, ready: bool) -> Any:
    return _call("status.publish", {"component": component, "enabled": enabled, "ready": ready})


def component_status(component: str) -> Any:
    return _call(component + ".status", {})


def component_ready(component: str) -> bool:
    """Report readiness, treating every failure to ask as not ready."""
    try:
        value = component_status(component)
        return value["enabled"] and value["ready"] and not value["stale"]
    except (OSError, RuntimeError, KeyError):
        return False


class DeskPilotStatusHeartbeat:
    """Publishes a component's liveness only after its real adapter is up.

    Construction is deliberately not initialization: nothing is published until
    ``start_after_initialization`` is called, so a component can never appear
    ready before the adapter it stands for actually works.
    """

    def __init__(
        self,
        component: str,
        publish: Callable[..., Any] = publish_status,
        wait: Callable[[threading.Event, float], bool] | None = None,
        on_unhealthy: Callable[[BaseException], Any] | None = None,
    ):
        if component not in COMPONENTS:
            raise ValueError("invalid component")
        self.component = component
        self.publish = publish
        self.wait = wait or (lambda stopped, seconds: stopped.wait(seconds))
        self.on_unhealthy = on_unhealthy or (lambda error: None)
        self.stopped = threading.Event()
        self.thread: threading.Thread | None = None
        self.enabled = False
        self.ready = False
        self.down = False

    def start_after_initialization(self, enabled: bool, ready: bool) -> None:
        if self.thread is not None:
            raise RuntimeError("status heartbeat already started")
        self.enabled = bool(enabled)
        self.ready = bool(ready)
        # A failed startup publication is fatal: it propagates to the caller so
        # the component refuses to come up rather than running unobserved.
        self.publish(self.component, self.enabled, self.ready)
        self.thread = threading.Thread(
            target=self._run, name=f"deskpilot-{self.component}-status", daemon=True
        )
        self.thread.start()

    def _run(self) -> None:
        while not self.wait(self.stopped, HEARTBEAT_INTERVAL_SECONDS):
            try:
                self.publish(self.component, self.enabled, self.ready)
            except Exception as error:
                self.down = True
                self.ready = False
                self.on_unhealthy(error)
                try:
                    self.publish(self.component, self.enabled, False)
                except Exception:
                    pass
                return

    def _finish(self, error: BaseException | None = None) -> None:
        if self.thread is None or self.down:
            return
        self.down = True
        self.ready = False
        self.stopped.set()
        if self.thread is not threading.current_thread():
            self.thread.join(timeout=1)
        try:
            self.publish(self.component, self.enabled, False)
        except Exception as publish_error:
            self.on_unhealthy(publish_error)
        if error is not None:
            self.on_unhealthy(error)

    def stop(self) -> None:
        self._finish()

    def adapter_failed(self, error: BaseException) -> None:
        self._finish(error)


if __name__ == "__main__":
    HermesStatusServer().serve()
