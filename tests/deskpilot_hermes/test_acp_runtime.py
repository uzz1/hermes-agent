import os
import json
import asyncio
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import acp
from acp.connection import Connection, StreamDirection, StreamEvent
from acp.schema import (
    AllowedOutcome,
    RequestPermissionRequest,
    RequestPermissionResponse,
    TextContentBlock,
)
from acp.utils import request_model

from acp_adapter.server import HermesACPAgent
from acp_adapter.session import SessionManager, _expand_acp_enabled_toolsets
from deskpilot_hermes.policy import PolicyReply
from deskpilot_hermes.runtime_context import (
    require_admitted_request,
    require_trusted_user_request,
    wait_for_local_approval,
)
from deskpilot_hermes.ui_lease import LiveUILeaseReader
from deskpilot_hermes.acp_permissions import ACPPermissionBridge


def _admission(*, admitted: bool = True) -> PolicyReply:
    return PolicyReply(
        {
            "admitted": admitted,
            "admissionID": str(uuid4()) if admitted else None,
            "entryPoint": "ui",
            "sender": None,
            "principal": "local-ui" if admitted else None,
            "expiresAt": (
                (datetime.now(UTC) + timedelta(minutes=1)).isoformat()
                if admitted
                else None
            ),
            "ruleID": "admission.allowed"
            if admitted
            else "admission.ui_lease_required",
            "reason": "verified live UI lease" if admitted else "lease denied",
        },
        "policy.ok",
        "authorized",
    )


class FakePolicy:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        return self.replies.pop(0)


class FakeLeaseReader:
    def __init__(self, lease="verified-ui-lease"):
        self.lease = lease
        self.calls = 0

    def read(self):
        self.calls += 1
        if isinstance(self.lease, BaseException):
            raise self.lease
        return self.lease


class FakeAgent:
    model = "deskpilot-glm"

    def __init__(self):
        self.calls = []
        self.tool_progress_callback = None
        self.thinking_callback = None
        self.reasoning_callback = None
        self.step_callback = None
        self.stream_delta_callback = None
        self.session_id = "internal-session"

    def run_conversation(self, **kwargs):
        self.calls.append((
            require_admitted_request(),
            require_trusted_user_request(),
            kwargs,
        ))
        return {"final_response": "done", "messages": []}


class PermissionAgent(FakeAgent):
    def run_conversation(self, **kwargs):
        import json

        import model_tools

        self.calls.append(
            json.loads(model_tools.handle_function_call("browser_open", {}))
        )
        return {"final_response": "done", "messages": []}


class ApprovalDispatcher:
    def __init__(self, authorization):
        self.authorization = authorization

    def dispatch(self, *, admitted, tool_name, arguments):
        assert admitted is require_admitted_request()
        assert (tool_name, arguments) == ("browser_open", {})
        capability = wait_for_local_approval(self.authorization)
        if capability is None:
            raise PermissionError("approval denied")
        return {"capability": capability}


class FakeRawConnection:
    def __init__(self):
        self.observers = []

    def add_observer(self, observer):
        self.observers.append(observer)


class FakeACPClient:
    def __init__(self, *, emit=True):
        self._conn = FakeRawConnection()
        self.emit = emit
        self.permission_calls = []
        self.updates = []

    async def request_permission(self, **kwargs):
        self.permission_calls.append(kwargs)
        if self.emit:
            params = {
                "sessionId": kwargs["session_id"],
                "toolCall": kwargs["tool_call"].model_dump(
                    mode="json", by_alias=True, exclude_none=True
                ),
                "options": [
                    item.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for item in kwargs["options"]
                ],
                "_meta": {"deskpilot": kwargs["deskpilot"]},
            }
            event = StreamEvent(
                StreamDirection.OUTGOING,
                {
                    "jsonrpc": "2.0",
                    "id": 41,
                    "method": "session/request_permission",
                    "params": params,
                },
            )
            for observer in self._conn.observers:
                observer(event)
        return RequestPermissionResponse(
            outcome=AllowedOutcome(optionId="allow_once", outcome="selected")
        )

    async def session_update(self, session_id, update):
        self.updates.append((session_id, update))


def _authorization():
    return {
        "decision": {
            "risk": "mutation",
            "verdict": "ask",
            "ruleID": "mutation.ask",
            "reason": "local approval required",
        },
        "actionDigest": "sha256:" + "a" * 64,
        "pendingApprovalID": str(uuid4()),
        "expiresAt": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }


@pytest.mark.asyncio
async def test_real_acp_connection_observer_runs_only_after_sender_send():
    order = []

    class Sender:
        async def send(self, payload):
            order.append(("send", payload["id"]))

        async def close(self):
            pass

    async def handler(_method, _params, _is_notification):
        return None

    connection = Connection(
        handler,
        object(),
        object(),
        listening=False,
        sender_factory=lambda _writer, _tasks: Sender(),
    )

    class Client:
        _conn = connection

        async def request_permission(
            self, *, session_id, tool_call, options, deskpilot
        ):
            return await request_model(
                connection,
                acp.CLIENT_METHODS["session_request_permission"],
                RequestPermissionRequest(
                    sessionId=session_id,
                    toolCall=tool_call,
                    options=options,
                    _meta={"deskpilot": deskpilot},
                ),
                RequestPermissionResponse,
            )

    bridge = ACPPermissionBridge()
    client = Client()
    bridge.connect(client)
    connection.add_observer(
        lambda event: order.append(("observer", event.message.get("id")))
    )
    authorization = _authorization()
    pending = bridge.requester(client, asyncio.get_running_loop(), "session-1")({
        "routeID": str(uuid4()),
        "pendingApprovalID": authorization["pendingApprovalID"],
        "decision": authorization["decision"],
        "expiresAt": authorization["expiresAt"],
    })

    assert await asyncio.to_thread(pending.wait_emitted, 1.0) is True
    assert order == [("send", 0), ("observer", 0)]
    assert pending.rpc_id == 0
    pending.cancel()
    await connection.close()


def _write_lease(path: Path, **updates):
    value = {
        "uiLease": "lease-from-signed-app",
        "pid": os.getpid(),
        "expiresAt": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }
    value.update(updates)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


def test_live_ui_lease_reader_accepts_private_current_process(tmp_path):
    path = tmp_path / "ui-lease"
    _write_lease(path)
    verifier = lambda pid: pid == os.getpid()
    assert LiveUILeaseReader(path, verifier).read() == "lease-from-signed-app"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda path: path.chmod(0o644),
        lambda path: path.unlink(),
        lambda path: _write_lease(path, pid=0),
        lambda path: _write_lease(
            path, expiresAt=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        ),
        lambda path: _write_lease(path, extra="not-closed"),
    ],
)
def test_live_ui_lease_reader_fails_closed(monkeypatch, tmp_path, mutation):
    path = tmp_path / "ui-lease"
    _write_lease(path)
    mutation(path)
    with pytest.raises((
        FileNotFoundError,
        PermissionError,
        ProcessLookupError,
        ValueError,
    )):
        LiveUILeaseReader(path, lambda _pid: True).read()


def test_live_ui_lease_reader_rejects_symlink(tmp_path):
    target = tmp_path / "target"
    _write_lease(target)
    path = tmp_path / "ui-lease"
    path.symlink_to(target)
    with pytest.raises(PermissionError, match="regular file"):
        LiveUILeaseReader(path, lambda _pid: True).read()


def test_default_ui_lease_requires_private_deskpilot_ancestors(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    deskpilot_dir = tmp_path / ".deskpilot"
    run_dir = deskpilot_dir / "run"
    run_dir.mkdir(parents=True)
    deskpilot_dir.chmod(0o755)
    run_dir.chmod(0o700)
    _write_lease(run_dir / "ui-lease")

    with pytest.raises(PermissionError, match="ancestor"):
        LiveUILeaseReader(identity_verifier=lambda _pid: True).read()

    deskpilot_dir.chmod(0o700)
    assert (
        LiveUILeaseReader(identity_verifier=lambda _pid: True).read()
        == "lease-from-signed-app"
    )


def test_ui_lease_reader_rejects_oversized_record(tmp_path):
    path = tmp_path / "ui-lease"
    value = _write_lease(path)
    value["uiLease"] = "x" * 5000
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="maximum size"):
        LiveUILeaseReader(path, lambda _pid: True).read()


def test_live_ui_lease_reader_rejects_unverified_process(tmp_path):
    path = tmp_path / "ui-lease"
    _write_lease(path)
    with pytest.raises(PermissionError, match="signing identity"):
        LiveUILeaseReader(path, lambda _pid: False).read()


def test_deskpilot_session_admits_ui_before_agent_construction(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    events = []
    policy = FakePolicy([_admission()])
    lease = FakeLeaseReader()

    def factory():
        events.append("agent")
        return FakeAgent()

    manager = SessionManager(
        agent_factory=factory,
        deskpilot_policy_client=policy,
        deskpilot_lease_reader=lease,
    )
    state = manager.create_session(".")

    assert state.admitted_request.provenance.entry_point == "ui"
    assert state.admitted_request.provenance.sender is None
    assert lease.calls == 1
    assert policy.calls == [
        (
            "admit",
            {
                "entryPoint": "ui",
                "sender": None,
                "uiLease": "verified-ui-lease",
                "jobID": None,
                "actionID": None,
                "actionVersion": 1,
                "inputDigest": None,
            },
        )
    ]
    assert events == ["agent"]


@pytest.mark.parametrize(
    "reader,replies",
    [
        (FakeLeaseReader(FileNotFoundError("missing")), []),
        (FakeLeaseReader(), [_admission(admitted=False)]),
        (FakeLeaseReader(), [PolicyReply(None, "policy.transport_denied", "timeout")]),
    ],
)
def test_deskpilot_session_denial_constructs_no_agent(monkeypatch, reader, replies):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    constructed = []
    manager = SessionManager(
        agent_factory=lambda: constructed.append(True),
        deskpilot_policy_client=FakePolicy(replies),
        deskpilot_lease_reader=reader,
    )

    with pytest.raises(PermissionError, match="DeskPilot UI admission denied"):
        manager.create_session(".")
    assert constructed == []


def test_restore_denial_recreates_no_agent(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    constructed = []

    class RestoreDB:
        def get_session(self, session_id):
            return {
                "id": session_id,
                "source": "acp",
                "model": "deskpilot-glm",
                "model_config": json.dumps({"cwd": "/tmp"}),
            }

        def get_messages_as_conversation(self, session_id):
            return []

    manager = SessionManager(
        agent_factory=lambda: constructed.append(True),
        db=RestoreDB(),
        deskpilot_policy_client=FakePolicy([_admission(admitted=False)]),
        deskpilot_lease_reader=FakeLeaseReader(),
    )

    assert manager.get_session("restored-session") is None
    assert constructed == []


def test_fork_reacquires_admission_before_new_agent(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    agents = []

    def factory():
        agent = FakeAgent()
        agents.append(agent)
        return agent

    manager = SessionManager(
        agent_factory=factory,
        deskpilot_policy_client=FakePolicy([_admission(), _admission(admitted=False)]),
        deskpilot_lease_reader=FakeLeaseReader(),
    )
    original = manager.create_session(".")

    with pytest.raises(PermissionError, match="DeskPilot UI admission denied"):
        manager.fork_session(original.session_id, ".")
    assert agents == [original.agent]


@pytest.mark.asyncio
async def test_prompt_refreshes_admission_and_binds_exact_turn_context(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    first = _admission()
    second = _admission()
    policy = FakePolicy([first, second])
    lease = FakeLeaseReader()
    agent = FakeAgent()
    manager = SessionManager(
        agent_factory=lambda: agent,
        db=SimpleNamespace(),
        deskpilot_policy_client=policy,
        deskpilot_lease_reader=lease,
    )
    state = manager.create_session(".")
    server = HermesACPAgent(manager)

    response = await server.prompt(
        [TextContentBlock(type="text", text="open the reviewed page")],
        state.session_id,
    )

    assert response.stop_reason == "end_turn"
    assert len(agent.calls) == 1
    admitted, trusted, kwargs = agent.calls[0]
    assert admitted.admission_id == second.result["admissionID"]
    assert trusted == "open the reviewed page"
    assert kwargs["user_message"] == "open the reviewed page"
    assert state.admitted_request is admitted
    assert lease.calls == 2
    assert [method for method, _ in policy.calls] == ["admit", "admit"]


@pytest.mark.asyncio
async def test_prompt_admission_denial_never_dispatches_model(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    policy = FakePolicy([_admission(), _admission(admitted=False)])
    agent = FakeAgent()
    manager = SessionManager(
        agent_factory=lambda: agent,
        db=SimpleNamespace(),
        deskpilot_policy_client=policy,
        deskpilot_lease_reader=FakeLeaseReader(),
    )
    state = manager.create_session(".")

    response = await HermesACPAgent(manager).prompt(
        [TextContentBlock(type="text", text="do not run")], state.session_id
    )

    assert response.stop_reason == "refusal"
    assert agent.calls == []
    assert state.is_running is False


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["/compact", "/steer corrected target"])
async def test_slash_commands_require_fresh_prompt_admission(monkeypatch, command):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    policy = FakePolicy([_admission(), _admission(admitted=False)])
    agent = FakeAgent()
    agent.compact = lambda *_args, **_kwargs: pytest.fail(
        "compact ran before admission"
    )
    agent.steer = lambda *_args, **_kwargs: pytest.fail("steer ran before admission")
    manager = SessionManager(
        agent_factory=lambda: agent,
        deskpilot_policy_client=policy,
        deskpilot_lease_reader=FakeLeaseReader(),
    )
    state = manager.create_session(".")

    response = await HermesACPAgent(manager).prompt(
        [TextContentBlock(type="text", text=command)], state.session_id
    )

    assert response.stop_reason == "refusal"
    assert agent.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("method_name", ["load_session", "resume_session"])
async def test_load_and_resume_reacquire_admission(monkeypatch, method_name):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    manager = SessionManager(
        agent_factory=FakeAgent,
        deskpilot_policy_client=FakePolicy([_admission(), _admission()]),
        deskpilot_lease_reader=FakeLeaseReader(),
    )
    state = manager.create_session(".")
    original = state.admitted_request
    server = HermesACPAgent(manager)

    response = await getattr(server, method_name)(".", state.session_id)

    assert response is not None
    assert state.admitted_request is not original


@pytest.mark.asyncio
@pytest.mark.parametrize("method_name", ["load_session", "resume_session"])
async def test_load_and_resume_denial_fails_closed(monkeypatch, method_name):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    manager = SessionManager(
        agent_factory=FakeAgent,
        deskpilot_policy_client=FakePolicy([_admission(), _admission(admitted=False)]),
        deskpilot_lease_reader=FakeLeaseReader(),
    )
    state = manager.create_session(".")

    with pytest.raises(PermissionError, match="DeskPilot UI admission denied"):
        await getattr(HermesACPAgent(manager), method_name)(".", state.session_id)


@pytest.mark.asyncio
async def test_deskpilot_ignores_acp_client_mcp_metadata(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    server = HermesACPAgent(SessionManager(agent_factory=FakeAgent))
    state = SimpleNamespace(session_id="session-1")
    touched = []
    monkeypatch.setattr(
        "tools.mcp_tool.register_mcp_servers",
        lambda *_args, **_kwargs: touched.append(True),
    )

    await server._register_session_mcp_servers(
        state, [SimpleNamespace(name="attacker")]
    )

    assert touched == []


def test_deskpilot_acp_toolset_is_exact_and_suppresses_mcp(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    assert _expand_acp_enabled_toolsets(
        ["deskpilot", "no_mcp"], ["browseros", "attacker"]
    ) == ["deskpilot"]


@pytest.mark.parametrize(
    "configured",
    [None, [], ["deskpilot"], ["no_mcp", "deskpilot"], ["deskpilot", "no_mcp", "web"]],
)
def test_deskpilot_acp_rejects_nonexact_toolset_config(monkeypatch, configured):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    with pytest.raises(RuntimeError, match="requires \\[deskpilot,no_mcp\\]"):
        _expand_acp_enabled_toolsets(configured, ["browseros"])


def test_ordinary_acp_toolset_expansion_is_unchanged(monkeypatch):
    monkeypatch.delenv("DESKPILOT_MODE", raising=False)
    assert _expand_acp_enabled_toolsets(["hermes-acp"], ["browseros"]) == [
        "hermes-acp",
        "mcp-browseros",
    ]


@pytest.mark.asyncio
async def test_public_dispatch_waits_for_exact_emitted_acp_permission(monkeypatch):
    import deskpilot_hermes.runtime_context as runtime_context

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    authorization = _authorization()
    capability = "local-capability"
    policy_event = {
        "type": "approval.resolved",
        "eventID": str(uuid4()),
        "pendingApprovalID": authorization["pendingApprovalID"],
        "routeID": None,
        "sessionID": None,
        "permissionRequestID": None,
        "resolution": "approve",
        "confirmationCapability": capability,
    }

    class SubscriptionPolicy:
        def subscribe_approval(self, pending_id, route_id, session_id, permission_id):
            assert pending_id == authorization["pendingApprovalID"]
            policy_event.update(
                routeID=route_id,
                sessionID=session_id,
                permissionRequestID=permission_id,
            )
            return dict(policy_event)

    monkeypatch.setattr(runtime_context, "ParentPolicyClient", SubscriptionPolicy)
    policy = FakePolicy([_admission(), _admission()])
    agent = PermissionAgent()
    dispatcher = ApprovalDispatcher(authorization)
    manager = SessionManager(
        agent_factory=lambda: agent,
        db=SimpleNamespace(),
        deskpilot_policy_client=policy,
        deskpilot_lease_reader=FakeLeaseReader(),
        deskpilot_tool_dispatcher=dispatcher,
    )
    state = manager.create_session(".")
    server = HermesACPAgent(manager)
    client = FakeACPClient()
    server.on_connect(client)

    response = await server.prompt(
        [TextContentBlock(type="text", text="open the reviewed page")], state.session_id
    )

    assert response.stop_reason == "end_turn"
    assert agent.calls == [{"capability": capability}]
    assert len(client._conn.observers) == 1
    assert len(client.permission_calls) == 1
    call = client.permission_calls[0]
    meta = call["deskpilot"]
    assert meta == {
        "routeID": policy_event["routeID"],
        "sessionID": state.session_id,
        "permissionRequestID": policy_event["permissionRequestID"],
        "pendingApprovalID": authorization["pendingApprovalID"],
        "expiresAt": authorization["expiresAt"],
    }
    assert (
        call["tool_call"].raw_input["pendingApprovalID"]
        == authorization["pendingApprovalID"]
    )
    assert server._deskpilot_permission_bridge.last_rpc_id == 41


@pytest.mark.asyncio
async def test_missing_acp_emission_denies_public_dispatch(monkeypatch):
    import deskpilot_hermes.runtime_context as runtime_context

    monkeypatch.setenv("DESKPILOT_MODE", "1")
    monkeypatch.setattr(
        runtime_context,
        "ParentPolicyClient",
        lambda: pytest.fail("policy subscription opened before ACP emission"),
    )
    authorization = _authorization()
    agent = PermissionAgent()
    dispatcher = ApprovalDispatcher(authorization)
    manager = SessionManager(
        agent_factory=lambda: agent,
        db=SimpleNamespace(),
        deskpilot_policy_client=FakePolicy([_admission(), _admission()]),
        deskpilot_lease_reader=FakeLeaseReader(),
        deskpilot_tool_dispatcher=dispatcher,
    )
    state = manager.create_session(".")
    server = HermesACPAgent(manager)
    server.on_connect(FakeACPClient(emit=False))

    response = await server.prompt(
        [TextContentBlock(type="text", text="do not bypass emission")], state.session_id
    )

    assert response.stop_reason == "end_turn"
    assert agent.calls == [
        {
            "ok": False,
            "error": "deskpilot.policy_denied",
            "_meta": {
                "deskpilot": {
                    "ruleID": "execute.denied",
                    "reason": "PermissionError",
                }
            },
        }
    ]


@pytest.mark.asyncio
async def test_session_cancel_revokes_pending_permission_and_parent_trace(monkeypatch):
    monkeypatch.setenv("DESKPILOT_MODE", "1")
    bridge = ACPPermissionBridge()
    client = FakeACPClient(emit=False)
    bridge.connect(client)
    pending = bridge.requester(client, asyncio.get_running_loop(), "session-1")({
        "routeID": str(uuid4()),
        "pendingApprovalID": str(uuid4()),
        "decision": {"verdict": "ask"},
        "expiresAt": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    })
    cancelled = []
    monkeypatch.setattr(
        "deskpilot_hermes.policy.ParentPolicyClient.call",
        lambda _self, method, params: (
            cancelled.append((method, params))
            or PolicyReply(
                {
                    "cancelled": True,
                    "revokedCapabilityCount": 0,
                    "resolvedPendingApprovalCount": 1,
                },
                "policy.ok",
                "cancelled",
            )
        ),
    )
    admitted = _admission().result
    state = SimpleNamespace(
        session_id="session-1",
        cancel_event=SimpleNamespace(set=lambda: None),
        runtime_lock=threading.Lock(),
        is_running=False,
        current_prompt_text="",
        admitted_request=SimpleNamespace(
            admission_id=admitted["admissionID"],
            provenance=SimpleNamespace(trace_id=str(uuid4())),
        ),
    )
    manager = SimpleNamespace(get_session=lambda _session_id: state)
    server = HermesACPAgent(manager)
    server._deskpilot_permission_bridge = bridge

    await server.cancel("session-1")

    assert pending.wait_emitted(0.01) is False
    assert pending.wait(datetime.now(UTC) + timedelta(seconds=1)) is None
    assert cancelled == [
        (
            "cancel",
            {
                "admissionID": admitted["admissionID"],
                "traceID": state.admitted_request.provenance.trace_id,
                "reason": "acp.session_cancelled",
            },
        )
    ]


def test_default_lease_verifier_defers_to_the_configured_ui_identity(monkeypatch, tmp_path):
    """The reader must not pin its own identity.

    It resolves the closed allowlist the parent policy server reads, so both
    sides of the lease agree; with nothing configured that is production only,
    with ad-hoc signatures refused.
    """
    import deskpilot.config

    monkeypatch.delenv("DESKPILOT_CONFIG", raising=False)
    default = LiveUILeaseReader(tmp_path / "ui-lease").identity_verifier
    assert default.allowed_identifiers == frozenset({"com.uzz1.deskpilot"})
    assert default.allow_adhoc_signature is False

    sentinel = object()
    monkeypatch.setattr(deskpilot.config, "ui_identity_verifier", lambda *args: sentinel)
    assert LiveUILeaseReader(tmp_path / "ui-lease").identity_verifier is sentinel
    # An explicitly injected verifier still wins over the configured one.
    injected = lambda _pid: True
    assert LiveUILeaseReader(tmp_path / "ui-lease", injected).identity_verifier is injected
