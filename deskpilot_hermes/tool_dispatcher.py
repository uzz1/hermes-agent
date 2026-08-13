import json
import logging
from collections.abc import Mapping
from importlib import metadata, resources
from pathlib import Path
from typing import Any
from uuid import UUID

from deskpilot.actions import ActionRegistry, POSTCONDITIONS, PRECONDITIONS
from deskpilot.execution import (
    ActionEnvelope,
    ExecutionDenied,
    ExecutionGrant,
    ExecutionService,
)
from deskpilot.models import AuthorizationDecision

from deskpilot_hermes.integration import (
    TOOL_ACTIONS,
    AdmittedRequest,
    _validate_authorization_result,
    _validate_execute_result,
)
from deskpilot_hermes.policy import PolicyReply
from deskpilot_hermes.provenance import DeskPilotProvenance, require_provenance
from deskpilot_hermes.validation import validate_uuid


logger = logging.getLogger(__name__)

assert ActionRegistry.__module__ == "deskpilot.actions"

_ADAPTER_KEYS = frozenset({"hammerspoon", "browseros", "cua", "terminal", "file"})
_DISTRIBUTION_ACTIONS = "deskpilot/data/actions.yaml"


def _json_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise ValueError("JSON object required")
    return decoded


def _packaged_actions_path() -> Any:
    packaged = resources.files("deskpilot").joinpath("data", "actions.yaml")
    if packaged.is_file():
        return packaged

    distribution = metadata.distribution("deskpilot")
    declared = next(
        (
            item
            for item in distribution.files or ()
            if str(item) == _DISTRIBUTION_ACTIONS
        ),
        None,
    )
    if declared is None:
        raise FileNotFoundError(_DISTRIBUTION_ACTIONS)
    located = Path(distribution.locate_file(declared))
    if not located.is_file():
        raise FileNotFoundError(_DISTRIBUTION_ACTIONS)
    return located


def load_packaged_action_registry() -> ActionRegistry:
    """Load and validate the exact action registry shipped by DeskPilot."""
    return ActionRegistry.from_yaml(
        _packaged_actions_path(), PRECONDITIONS, POSTCONDITIONS
    )


class _BoundExecutor:
    def __init__(self, adapter: Any, action_id: str):
        self._adapter = adapter
        self._action_id = action_id

    def invoke(self, inputs: dict[str, Any]) -> dict[str, Any]:
        observed = self._adapter.execute(self._action_id, _json_snapshot(inputs))
        return _json_snapshot(observed)


class _ConsumedGate:
    def __init__(self, grant: ExecutionGrant):
        self._grant = grant

    def check(self, _envelope: ActionEnvelope) -> ExecutionGrant:
        return self._grant


class DeskPilotToolDispatcher:
    def __init__(
        self,
        policy: Any,
        adapters: Mapping[str, Any],
        environment: Mapping[str, Any],
        approval: Any,
    ):
        if set(adapters) != _ADAPTER_KEYS:
            raise ValueError("exact DeskPilot adapters required")
        checked_adapters = dict(adapters)
        for adapter in checked_adapters.values():
            if not callable(getattr(adapter, "execute", None)):
                raise ValueError("adapter execute method required")
            if hasattr(adapter, "invoke") or hasattr(
                adapter, "_handle_function_call_unchecked"
            ):
                raise ValueError("adapter exposes unchecked dispatch")
        if not callable(approval):
            raise ValueError("approval callback required")
        self._policy = policy
        self._adapters = checked_adapters
        self._environment = dict(environment)
        self._approval = approval
        self._registry = load_packaged_action_registry()

    def dispatch(
        self,
        admitted: AdmittedRequest,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            if type(admitted) is not AdmittedRequest:
                raise ValueError("admitted request required")
            if type(admitted.provenance) is not DeskPilotProvenance:
                raise ValueError("DeskPilot provenance required")
            if not isinstance(arguments, dict):
                raise ValueError("arguments must be an object")
            if require_provenance() != admitted.provenance:
                raise ValueError("active provenance mismatch")
            mapping = TOOL_ACTIONS.get(tool_name)
            if mapping is None:
                raise ValueError("unmapped tool")
            validate_uuid(admitted.admission_id)
            validate_uuid(admitted.provenance.trace_id)

            inputs = _json_snapshot(arguments)
            action_id, action_version = mapping
            bound = self._registry.resolve(action_id, action_version, inputs)

            authorization = self._policy.call(
                "authorize",
                {
                    "admissionID": admitted.admission_id,
                    "traceID": admitted.provenance.trace_id,
                    "actionID": action_id,
                    "actionVersion": action_version,
                    "inputs": _json_snapshot(dict(bound.inputs)),
                },
            )
            if not isinstance(authorization, PolicyReply):
                raise ValueError("authorization reply required")
            if authorization.result is None:
                raise ValueError("authorization denied")
            authorization_result = authorization.result
            decision_data, verdict = _validate_authorization_result(
                authorization_result
            )
            decision = AuthorizationDecision.model_validate(decision_data)
            if decision.risk != bound.spec.risk:
                raise ValueError("authorization risk mismatch")
            if verdict == "deny":
                raise ValueError("authorization denied")
            if verdict == "local_confirm" and admitted.provenance.entry_point != "ui":
                raise ValueError("local confirmation requires UI")

            capability = None
            if verdict in {"ask", "local_confirm"}:
                capability = self._approval(_json_snapshot(authorization_result))
                if not isinstance(capability, str) or not capability:
                    raise ValueError("approval capability required")

            action_digest = authorization_result["actionDigest"]
            execution = self._policy.call(
                "execute",
                {
                    "admissionID": admitted.admission_id,
                    "traceID": admitted.provenance.trace_id,
                    "actionDigest": action_digest,
                    "confirmationCapability": capability,
                },
            )
            if not isinstance(execution, PolicyReply) or execution.result is None:
                raise ValueError("execution reply required")
            if _validate_execute_result(execution.result) is not True:
                raise ValueError("execution denied")
            consumption_id = execution.result["consumptionID"]

            envelope = ActionEnvelope.model_validate({
                "admissionID": admitted.admission_id,
                "traceID": admitted.provenance.trace_id,
                "entryPoint": admitted.provenance.entry_point,
                "sender": admitted.provenance.sender,
                "action": bound.spec,
                "inputs": _json_snapshot(dict(bound.inputs)),
                "decision": decision,
                "consumptionID": consumption_id,
            })
            grant = ExecutionGrant(
                execute=True,
                consumptionID=UUID(consumption_id),
                admissionID=UUID(admitted.admission_id),
                traceID=UUID(admitted.provenance.trace_id),
                actionDigest=action_digest,
            )
            service = ExecutionService(
                {
                    bound.spec.executor: _BoundExecutor(
                        self._adapters[bound.spec.executor], action_id
                    )
                },
                _ConsumedGate(grant),
                bound=bound,
                preconditions=PRECONDITIONS,
                postconditions=POSTCONDITIONS,
                environment=self._environment,
            )
            observed = service.execute(envelope)
            if not isinstance(observed, dict):
                raise ValueError("observations must be an object")
            return observed
        except Exception as cause:
            # The model-facing message stays generic on purpose — a denial must
            # not teach the model how to shape a passing request. But dropping
            # the cause entirely made three distinct defects present identically
            # with no __cause__ to follow, so the real reason is logged locally.
            logger.warning(
                "DeskPilot execution denied for %s: %s: %s",
                tool_name, type(cause).__name__, cause,
            )
            raise ExecutionDenied("DeskPilot execution denied") from None
