import multiprocessing
import stat
import tempfile
import threading
import time
from pathlib import Path

import pytest

import deskpilot_hermes.status_server as status


@pytest.fixture
def tmp_path():
    # Overrides pytest's tmp_path. Its per-user macOS root exceeds the 104-byte
    # AF_UNIX sun_path limit, so binding a socket under it fails outright.
    with tempfile.TemporaryDirectory(prefix="dp-status-", dir="/private/tmp") as root:
        yield Path(root)


def test_store_disabled_ready_and_stale():
    now = [10.0]
    store = status.StatusStore(clock=lambda: now[0])
    assert store.read("gateway") == {"enabled": False, "ready": False, "stale": False}
    store.publish("gateway", True, True)
    store.publish("cua", True, True)
    assert store.read("gateway")["ready"] and store.read("cua")["ready"]
    now[0] += 16
    assert store.read("gateway") == {"enabled": True, "ready": False, "stale": True}


def test_dispatch_is_closed():
    server = status.HermesStatusServer(Path("unused"), status.StatusStore(clock=lambda: 1.0))
    with pytest.raises(ValueError):
        server.dispatch({"method": "shell", "params": {}})
    with pytest.raises(ValueError):
        server.dispatch(
            {
                "method": "status.publish",
                "params": {"component": "other", "enabled": True, "ready": True},
            }
        )


def test_private_socket_client_ready_disabled_and_missing(monkeypatch, tmp_path):
    path = tmp_path / "hermes-status.sock"
    monkeypatch.setattr(status, "SOCKET_PATH", path)
    process = multiprocessing.Process(target=status.HermesStatusServer(path).serve)
    process.start()
    try:
        for _ in range(100):
            if path.exists():
                break
            time.sleep(0.01)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert status.component_status("gateway") == {
            "enabled": False,
            "ready": False,
            "stale": False,
        }
        status.publish_status("gateway", True, True)
        status.publish_status("cua", True, True)
        assert status.component_ready("gateway") and status.component_ready("cua")
    finally:
        process.terminate()
        process.join()
        path.unlink(missing_ok=True)
    assert status.component_ready("cua") is False


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.condition = threading.Condition()
        self.targets = []

    def wait(self, stopped, seconds):
        with self.condition:
            target = self.now + seconds
            self.targets.append(target)
            self.condition.notify_all()
            while self.now < target and not stopped.is_set():
                self.condition.wait(0.01)
            return stopped.is_set()

    def advance(self, seconds):
        with self.condition:
            self.now += seconds
            self.condition.notify_all()


def eventually(predicate):
    for _ in range(100):
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


def test_heartbeat_at_zero_ten_twenty_and_no_stale_at_fifteen():
    clock = FakeClock()
    store = status.StatusStore(clock=lambda: clock.now)
    events = []

    def publish(component, enabled, ready):
        events.append((clock.now, enabled, ready))
        store.publish(component, enabled, ready)

    heartbeat = status.DeskPilotStatusHeartbeat("cua", publish=publish, wait=clock.wait)
    assert events == []  # construction is not initialization and must not publish
    heartbeat.start_after_initialization(True, True)
    assert events == [(0.0, True, True)]
    eventually(lambda: clock.targets == [10.0])
    clock.advance(10)
    eventually(lambda: len(events) == 2)
    eventually(lambda: clock.targets == [10.0, 20.0])
    clock.advance(5)
    assert store.read("cua") == {"enabled": True, "ready": True, "stale": False}
    clock.advance(5)
    eventually(lambda: len(events) == 3)
    assert [item[0] for item in events] == [0.0, 10.0, 20.0]
    heartbeat.stop()
    assert events[-1] == (20.0, True, False)


def test_startup_failure_is_fatal_and_adapter_failure_publishes_down():
    def refuse(*args):
        raise ConnectionError()

    with pytest.raises(ConnectionError):
        status.DeskPilotStatusHeartbeat("gateway", publish=refuse).start_after_initialization(
            True, True
        )
    events = []
    unhealthy = []
    heartbeat = status.DeskPilotStatusHeartbeat(
        "gateway", publish=lambda *args: events.append(args), on_unhealthy=unhealthy.append
    )
    heartbeat.start_after_initialization(True, True)
    failure = RuntimeError("adapter failed")
    heartbeat.adapter_failed(failure)
    assert events == [("gateway", True, True), ("gateway", True, False)]
    assert unhealthy == [failure]


def test_later_publication_failure_marks_runtime_unhealthy():
    clock = FakeClock()
    calls = []
    unhealthy = []

    def publish(*args):
        calls.append(args)
        if len(calls) > 1:
            raise ConnectionError("status server lost")

    heartbeat = status.DeskPilotStatusHeartbeat(
        "cua", publish=publish, wait=clock.wait, on_unhealthy=unhealthy.append
    )
    heartbeat.start_after_initialization(True, True)
    eventually(lambda: clock.targets == [10.0])
    clock.advance(10)
    eventually(lambda: bool(unhealthy))
    assert isinstance(unhealthy[0], ConnectionError) and heartbeat.ready is False


def test_cua_seam_publishes_only_after_real_initialization(monkeypatch):
    events = []

    class FakeHeartbeat:
        def __init__(self, component, on_unhealthy):
            self.component = component

        def start_after_initialization(self, enabled, ready):
            events.append((self.component, enabled, ready))

    import tools.computer_use.tool as computer_use_tool

    class Backend:
        def start(self):
            events.append("cua-adapter-started")

        def is_available(self):
            events.append("cua-adapter-ready")
            return True

        def stop(self):
            events.append("cua-adapter-stopped")

    monkeypatch.setattr(computer_use_tool, "DeskPilotStatusHeartbeat", FakeHeartbeat)
    monkeypatch.setattr(computer_use_tool, "CuaDriverBackend", Backend)
    monkeypatch.setattr(computer_use_tool, "_backend", None)
    monkeypatch.setenv("HERMES_COMPUTER_USE_BACKEND", "cua")
    computer_use_tool._get_backend()
    monkeypatch.setattr(computer_use_tool, "_backend", None)
    assert events.index("cua-adapter-ready") < events.index(("cua", True, True))


def test_cua_seam_refuses_an_unavailable_backend(monkeypatch):
    import tools.computer_use.tool as computer_use_tool

    stopped = []

    class Backend:
        def start(self):
            pass

        def is_available(self):
            return False

        def stop(self):
            stopped.append(True)

    class FailIfUsed:
        def __init__(self, component, on_unhealthy):
            raise AssertionError("heartbeat started for an unavailable backend")

    monkeypatch.setattr(computer_use_tool, "DeskPilotStatusHeartbeat", FailIfUsed)
    monkeypatch.setattr(computer_use_tool, "CuaDriverBackend", Backend)
    monkeypatch.setattr(computer_use_tool, "_backend", None)
    monkeypatch.setenv("HERMES_COMPUTER_USE_BACKEND", "cua")
    with pytest.raises(RuntimeError, match="AX backend not ready"):
        computer_use_tool._get_backend()
    assert stopped == [True]
    # A refused backend must not stay cached as a usable one.
    assert computer_use_tool._backend is None
