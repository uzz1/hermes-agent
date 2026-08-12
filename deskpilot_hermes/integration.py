import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable
from uuid import uuid4

from deskpilot_hermes.policy import ParentPolicyClient, PolicyReply
from deskpilot_hermes.provenance import DeskPilotProvenance, require_provenance


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


@dataclass(frozen=True)
class AdmittedRequest:
    provenance: DeskPilotProvenance
    admission_id: str


def _denied(rule_id: str, reason: str) -> tuple[None, PolicyReply]:
    return None, PolicyReply(None, rule_id, reason)


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
    result = reply.result
    if not isinstance(result, dict) or result.get("admitted") is not True:
        return None
    admission_id = result.get("admissionID")
    if not isinstance(admission_id, str) or not admission_id:
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
        canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
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
    result = reply.result
    if not isinstance(result, dict) or result.get("admitted") is not True:
        return None
    admission_id = result.get("admissionID")
    if not isinstance(admission_id, str) or not admission_id:
        return None
    return AdmittedRequest(
        DeskPilotProvenance("scheduler", sender, str(uuid4())), admission_id
    )


def guarded_tool_call(
    client: ParentPolicyClient,
    admitted: AdmittedRequest,
    tool_name: str,
    arguments: dict[str, Any],
    invoke: Callable[[], Any],
    await_local_approval: Callable[[dict[str, Any]], str | None],
) -> tuple[Any | None, PolicyReply]:
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

    action_id, version = mapping
    try:
        authorization = client.call(
            "authorize",
            {
                "admissionID": admitted.admission_id,
                "traceID": admitted.provenance.trace_id,
                "actionID": action_id,
                "actionVersion": version,
                "inputs": arguments,
            },
        )
        if not isinstance(authorization, PolicyReply):
            return _denied("policy.malformed_reply", "malformed authorization reply")
        if authorization.result is None:
            return None, authorization
        result = authorization.result
        decision = result["decision"]
        if not isinstance(decision, dict):
            raise ValueError("decision must be an object")
        verdict = decision["verdict"]
        if verdict not in {"allow", "deny", "ask", "local_confirm"}:
            raise ValueError("unknown verdict")
        if verdict == "deny":
            rule_id = decision["ruleID"]
            reason = decision["reason"]
            if not isinstance(rule_id, str) or not isinstance(reason, str):
                raise ValueError("denial fields must be strings")
            return _denied(rule_id, reason)

        capability = None
        if verdict in {"ask", "local_confirm"}:
            capability = await_local_approval(result)
            if not isinstance(capability, str) or not capability:
                return _denied("policy.approval_denied", "local approval unavailable")
        action_digest = result["actionDigest"]
        if not isinstance(action_digest, str) or not action_digest:
            raise ValueError("action digest missing")
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
        if not isinstance(grant.result, dict):
            return _denied("policy.malformed_reply", "malformed execution reply")
        execute = grant.result.get("execute")
        if execute is False:
            return None, grant
        if execute is not True:
            return _denied("policy.malformed_reply", "malformed execution reply")
    except (AttributeError, KeyError, TypeError, ValueError):
        return _denied("policy.malformed_reply", "malformed policy reply")
    except Exception as exc:
        return _denied("policy.transport_denied", type(exc).__name__)

    return invoke(), grant
