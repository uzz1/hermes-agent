import hashlib
import inspect
import json
import re
from dataclasses import dataclass
from typing import Any, Callable
from uuid import uuid4

from deskpilot_hermes.policy import ParentPolicyClient, PolicyReply
from deskpilot_hermes.provenance import DeskPilotProvenance, require_provenance
from deskpilot_hermes.validation import (
    nonempty_string,
    validate_bounded_future,
    validate_sha256,
    validate_uuid,
)


TELEGRAM = re.compile(r"^[1-9][0-9]*$")
SIGNAL = re.compile(
    r"^(?:\+[1-9][0-9]{7,14}|account:[A-Za-z0-9][A-Za-z0-9._-]{7,127})$"
)

TOOL_ACTIONS = {
    "hs_app_observe": ("app.observe", 1),
    "hs_app_focus": ("app.focus", 1),
    "hs_window_place": ("window.place", 1),
    "hs_zed_command_palette": ("zed.commandPalette", 1),
    "hs_ghostty_new_tab": ("ghostty.newTab", 1),
    "browser_open": ("browser.open", 1),
    "cua_observe": ("cua.observe", 1),
    "cua_focus": ("cua.focus", 1),
    "cua_click": ("cua.click", 1),
    "cua_type": ("cua.type", 1),
    "terminal_diagnostic": ("terminal.diagnostic", 1),
    "file_reveal": ("file.reveal", 1),
    "file_move": ("file.move", 1),
    "message_send": ("message.send", 1),
    "credential_change": ("credential.change", 1),
    "shell_destructive": ("shell.destructive", 1),
    "health_observe": ("health.observe", 1),
    "developer_digest": ("developer.digest", 1),
}

ACTION_EXECUTORS = {
    "app.observe": "hammerspoon",
    "app.focus": "hammerspoon",
    "window.place": "hammerspoon",
    "zed.commandPalette": "hammerspoon",
    "ghostty.newTab": "hammerspoon",
    "browser.open": "browseros",
    "message.send": "browseros",
    "credential.change": "browseros",
    "cua.observe": "cua",
    "cua.focus": "cua",
    "cua.click": "cua",
    "cua.type": "cua",
    "terminal.diagnostic": "terminal",
    "shell.destructive": "terminal",
    "health.observe": "terminal",
    "file.reveal": "file",
    "file.move": "file",
    "developer.digest": "file",
}

_AUTHORIZATION_FIELDS = {
    "decision",
    "actionDigest",
    "pendingApprovalID",
    "expiresAt",
}
_DECISION_FIELDS = {"risk", "verdict", "ruleID", "reason"}
_RISKS = {"observe", "reversible_local", "mutation", "sensitive", "prohibited"}
_VERDICTS = {"allow", "ask", "local_confirm", "deny"}
_EXECUTE_FIELDS = {"execute", "consumptionID", "ruleID", "reason"}
_ADMISSION_FIELDS = {
    "admitted",
    "ruleID",
    "reason",
    "admissionID",
    "entryPoint",
    "sender",
    "principal",
    "expiresAt",
}


@dataclass(frozen=True)
class AdmittedRequest:
    provenance: DeskPilotProvenance
    admission_id: str


def _denied(rule_id: str, reason: str) -> tuple[None, PolicyReply]:
    return None, PolicyReply(None, rule_id, reason)


def _canonical_arguments(arguments: dict[str, Any]) -> str:
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _invoker_mode(invoke: Callable[..., Any]) -> int | None:
    try:
        parameters = inspect.signature(invoke)
    except (TypeError, ValueError):
        return None
    try:
        parameters.bind({})
        return 1
    except (TypeError, ValueError):
        try:
            parameters.bind()
            return 0
        except (TypeError, ValueError):
            return None


def _nonempty_string(value: Any) -> bool:
    return nonempty_string(value)


def _validate_action_digest(value: Any) -> None:
    validate_sha256(value)


def _validate_uuid(value: Any) -> None:
    validate_uuid(value)


def _validate_admission_result(
    result: Any, entry_point: str, sender: str | None
) -> str | None:
    if not isinstance(result, dict) or set(result) != _ADMISSION_FIELDS:
        raise ValueError("admission result shape")
    admitted = result["admitted"]
    if type(admitted) is not bool:
        raise ValueError("admitted must be a literal boolean")
    if not _nonempty_string(result["ruleID"]) or not _nonempty_string(result["reason"]):
        raise ValueError("admission rule and reason required")
    if result["entryPoint"] != entry_point or result["sender"] != sender:
        raise ValueError("admission identity mismatch")

    admission_id = result["admissionID"]
    principal = result["principal"]
    expires_at = result["expiresAt"]
    if admitted:
        if not _nonempty_string(admission_id) or not _nonempty_string(principal):
            raise ValueError("successful admission identity required")
        _validate_uuid(admission_id)
        validate_bounded_future(expires_at)
        return admission_id
    if any(value is not None for value in (admission_id, principal, expires_at)):
        raise ValueError("denied admission must not carry admission state")
    return None


def admit_ui(client: ParentPolicyClient, ui_lease: str) -> AdmittedRequest | None:
    if not nonempty_string(ui_lease):
        return None
    try:
        reply = client.call(
            "admit",
            {
                "entryPoint": "ui",
                "sender": None,
                "uiLease": ui_lease,
                "jobID": None,
                "actionID": None,
                "actionVersion": 1,
                "inputDigest": None,
            },
        )
    except Exception:
        return None
    if not isinstance(reply, PolicyReply):
        return None
    try:
        admission_id = _validate_admission_result(reply.result, "ui", None)
    except (TypeError, ValueError):
        return None
    if admission_id is None:
        return None
    return AdmittedRequest(DeskPilotProvenance("ui", None, str(uuid4())), admission_id)


def _validate_authorization_result(result: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(result, dict) or set(result) != _AUTHORIZATION_FIELDS:
        raise ValueError("authorization result shape")
    decision = result["decision"]
    if not isinstance(decision, dict) or set(decision) != _DECISION_FIELDS:
        raise ValueError("decision shape")
    if decision["risk"] not in _RISKS or decision["verdict"] not in _VERDICTS:
        raise ValueError("decision enumeration")
    if not _nonempty_string(decision["ruleID"]) or not _nonempty_string(
        decision["reason"]
    ):
        raise ValueError("decision rule and reason required")

    verdict = decision["verdict"]
    action_digest = result["actionDigest"]
    pending_id = result["pendingApprovalID"]
    expires_at = result["expiresAt"]
    if verdict == "deny":
        if action_digest is not None:
            _validate_action_digest(action_digest)
        if pending_id is not None or expires_at is not None:
            raise ValueError("deny must not carry pending approval")
    elif verdict == "allow":
        _validate_action_digest(action_digest)
        if pending_id is not None or expires_at is not None:
            raise ValueError("allow must not carry pending approval")
    else:
        _validate_action_digest(action_digest)
        _validate_uuid(pending_id)
        validate_bounded_future(expires_at)
    return decision, verdict


def _validate_execute_result(result: Any) -> bool:
    if not isinstance(result, dict) or set(result) != _EXECUTE_FIELDS:
        raise ValueError("execute result shape")
    execute = result["execute"]
    if type(execute) is not bool:
        raise ValueError("execute must be a literal boolean")
    if not _nonempty_string(result["ruleID"]) or not _nonempty_string(result["reason"]):
        raise ValueError("execute rule and reason required")
    consumption_id = result["consumptionID"]
    if execute:
        _validate_uuid(consumption_id)
    elif consumption_id is not None:
        raise ValueError("denied execute must not carry consumption ID")
    return execute


def admit_sender(
    client: ParentPolicyClient,
    platform: str,
    sender_id: str,
    construct_agent: Callable[[AdmittedRequest], Any],
) -> Any | None:
    if platform == "telegram":
        pattern = TELEGRAM
    elif platform == "signal":
        pattern = SIGNAL
    else:
        return None
    if not isinstance(sender_id, str) or pattern.fullmatch(sender_id) is None:
        return None

    sender = f"{platform}:{sender_id}"
    reply = client.call(
        "admit",
        {
            "entryPoint": platform,
            "sender": sender,
            "uiLease": None,
            "jobID": None,
            "actionID": None,
            "actionVersion": 1,
            "inputDigest": None,
        },
    )
    if not isinstance(reply, PolicyReply):
        return None
    try:
        admission_id = _validate_admission_result(reply.result, platform, sender)
    except (TypeError, ValueError):
        return None
    if admission_id is None:
        return None
    request = AdmittedRequest(
        DeskPilotProvenance(platform, sender, str(uuid4())), admission_id
    )
    return construct_agent(request)


def admit_scheduled(
    client: ParentPolicyClient, compiled: dict[str, Any]
) -> AdmittedRequest | None:
    required = {"jobID", "actionID", "actionVersion", "inputDigest", "inputs"}
    if not isinstance(compiled, dict) or set(compiled) != required:
        return None
    if type(compiled["actionVersion"]) is not int or compiled["actionVersion"] != 1:
        return None
    job_id = compiled["jobID"]
    action_id = compiled["actionID"]
    input_digest = compiled["inputDigest"]
    inputs = compiled["inputs"]
    if not isinstance(job_id, str) or not job_id:
        return None
    if not isinstance(action_id, str) or not action_id:
        return None
    if not isinstance(input_digest, str) or not input_digest:
        return None
    if not isinstance(inputs, dict):
        return None
    try:
        canonical = json.dumps(
            inputs, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError):
        return None
    expected_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if input_digest != expected_digest:
        return None

    sender = f"job:{job_id}"
    reply = client.call(
        "admit",
        {
            "entryPoint": "scheduler",
            "sender": sender,
            "uiLease": None,
            "jobID": job_id,
            "actionID": action_id,
            "actionVersion": 1,
            "inputDigest": input_digest,
        },
    )
    if not isinstance(reply, PolicyReply):
        return None
    try:
        admission_id = _validate_admission_result(reply.result, "scheduler", sender)
    except (TypeError, ValueError):
        return None
    if admission_id is None:
        return None
    return AdmittedRequest(
        DeskPilotProvenance("scheduler", sender, str(uuid4())), admission_id
    )


def guarded_tool_call(
    client: ParentPolicyClient,
    admitted: AdmittedRequest,
    tool_name: str,
    arguments: dict[str, Any],
    invoke: Callable[..., Any],
    await_local_approval: Callable[[dict[str, Any]], str | None],
) -> tuple[Any | None, PolicyReply]:
    """Deprecated private bridge pending the typed Task 11 dispatcher.

    One-argument invokers receive a fresh copy of the authorized inputs. The
    zero-argument form remains solely for legacy plan tests; arity validation
    cannot prove what an unrelated closure captures, so production seams must
    not import this helper.
    """
    try:
        current = require_provenance()
    except PermissionError:
        return _denied("policy.provenance_denied", "provenance missing")
    if current != admitted.provenance:
        return _denied("policy.provenance_denied", "provenance mismatch")
    mapping = TOOL_ACTIONS.get(tool_name)
    if mapping is None:
        return _denied("policy.unmapped_tool", "tool has no DeskPilot action")
    if not isinstance(arguments, dict):
        return _denied("policy.invalid_arguments", "tool arguments must be an object")
    try:
        _validate_uuid(admitted.admission_id)
    except (TypeError, ValueError):
        return _denied("policy.invalid_admission", "admission ID must be canonical")
    invoker_mode = _invoker_mode(invoke)
    if invoker_mode is None:
        return _denied(
            "policy.invalid_invoker", "invoker must accept zero or one input"
        )
    try:
        canonical_arguments = _canonical_arguments(arguments)
    except (TypeError, ValueError):
        return _denied("policy.invalid_arguments", "tool arguments must be strict JSON")

    def arguments_unchanged() -> bool:
        try:
            return _canonical_arguments(arguments) == canonical_arguments
        except (TypeError, ValueError):
            return False

    action_id, version = mapping
    try:
        authorization = client.call(
            "authorize",
            {
                "admissionID": admitted.admission_id,
                "traceID": admitted.provenance.trace_id,
                "actionID": action_id,
                "actionVersion": version,
                "inputs": json.loads(canonical_arguments),
            },
        )
        if not isinstance(authorization, PolicyReply):
            return _denied("policy.malformed_reply", "malformed authorization reply")
        if authorization.result is None:
            return None, authorization
        result = authorization.result
        decision, verdict = _validate_authorization_result(result)
        action_digest = result["actionDigest"]
        if verdict == "deny":
            return _denied(decision["ruleID"], decision["reason"])
        if verdict == "local_confirm" and admitted.provenance.entry_point != "ui":
            return _denied(
                "policy.approval_denied", "local confirmation requires UI provenance"
            )

        capability = None
        if verdict in {"ask", "local_confirm"}:
            capability = await_local_approval(
                json.loads(json.dumps(result, separators=(",", ":")))
            )
            if not isinstance(capability, str) or not capability:
                return _denied("policy.approval_denied", "local approval unavailable")
        if not arguments_unchanged():
            return _denied("policy.arguments_changed", "tool arguments changed")
        grant = client.call(
            "execute",
            {
                "admissionID": admitted.admission_id,
                "traceID": admitted.provenance.trace_id,
                "actionDigest": action_digest,
                "confirmationCapability": capability,
            },
        )
        if not isinstance(grant, PolicyReply):
            return _denied("policy.malformed_reply", "malformed execution reply")
        if grant.result is None:
            return None, grant
        if _validate_execute_result(grant.result) is False:
            return None, grant
    except (AttributeError, KeyError, TypeError, ValueError):
        return _denied("policy.malformed_reply", "malformed policy reply")
    except Exception as exc:
        return _denied("policy.transport_denied", type(exc).__name__)

    if not arguments_unchanged():
        return _denied("policy.arguments_changed", "tool arguments changed")
    if invoker_mode == 1:
        return invoke(json.loads(canonical_arguments)), grant
    return invoke(), grant
