import json
import os
import shutil
import socket
import stat
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from deskpilot.executors.hammerspoon import HammerspoonExecutor, SubprocessRunner
from deskpilot.traces import TraceStore
from deskpilot_hermes.integration import ACTION_EXECUTORS
from deskpilot_hermes.policy import ParentPolicyClient
from deskpilot_hermes.runtime_context import (
    set_tool_dispatcher,
    wait_for_local_approval,
)
from deskpilot_hermes.tool_dispatcher import DeskPilotToolDispatcher
from tools.registry import registry


def _runtime_tool_ready(name, arguments):
    entry = registry.get_entry(name)
    if entry is None or not isinstance(entry.schema.get("parameters"), dict):
        return False
    if list(Draft202012Validator(entry.schema["parameters"]).iter_errors(arguments)):
        return False
    return entry.check_fn is None or entry.check_fn() is True


def _runtime_call(name, args):
    entry = registry.get_entry(name)
    if entry is None:
        raise RuntimeError(f"required runtime tool missing: {name}")
    schema = entry.schema.get("parameters")
    if not isinstance(schema, dict):
        raise RuntimeError("runtime tool parameters missing")
    if list(Draft202012Validator(schema).iter_errors(args)):
        raise RuntimeError(f"runtime tool schema mismatch: {name}")
    if entry.check_fn is not None and entry.check_fn() is not True:
        raise RuntimeError(f"runtime tool unavailable: {name}")
    raw = registry.dispatch(name, args)
    if not isinstance(raw, str):
        raise RuntimeError("runtime tool returned non-string JSON")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("runtime tool returned malformed JSON") from error
    if not isinstance(payload, dict):
        raise RuntimeError("runtime tool result must be an object")
    if (
        payload.get("error") not in (None, "")
        or payload.get("ok") is False
        or payload.get("success") is False
    ):
        raise RuntimeError("runtime tool reported an error")
    if "exit_code" in payload and (
        type(payload["exit_code"]) is not int or payload["exit_code"] != 0
    ):
        raise RuntimeError("runtime tool returned nonzero or malformed exit code")
    return payload


def _canonical_https_url(value):
    parts = urlsplit(value)
    if (
        parts.scheme.casefold() != "https"
        or not parts.hostname
        or parts.username
        or parts.password
    ):
        raise RuntimeError("runtime returned an invalid HTTPS URL")
    try:
        port = parts.port
    except ValueError as error:
        raise RuntimeError("runtime returned an invalid URL port") from error
    return (
        "https",
        parts.hostname.casefold(),
        port or 443,
        parts.path or "/",
        parts.query,
        parts.fragment,
    )


def _url_fields(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "url" and isinstance(child, str):
                yield child
            else:
                yield from _url_fields(child)
    elif isinstance(value, list):
        for child in value:
            yield from _url_fields(child)
    elif isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return
        if decoded != value:
            yield from _url_fields(decoded)


def _require_action(payload, action):
    if payload.get("ok") is not True or payload.get("action") != action:
        raise RuntimeError(f"runtime action unverified: {action}")


def _valid_ax_element(item):
    return (
        isinstance(item, dict)
        and type(item.get("index")) is int
        and item["index"] > 0
        and isinstance(item.get("role"), str)
        and 0 < len(item["role"]) <= 128
        and isinstance(item.get("label"), str)
        and len(item["label"]) <= 512
        and isinstance(item.get("app"), str)
        and len(item["app"]) <= 512
        and isinstance(item.get("bounds"), list)
        and len(item["bounds"]) == 4
        and all(type(value) is int for value in item["bounds"])
    )


class BrowserMessagingAdapter:
    ACCOUNT_SECURITY_URLS = {
        "github": "https://github.com/settings/security",
        "payment": "https://pay.google.com/gp/w/u/0/home/settings",
    }

    def _navigate_verified(self, url):
        _runtime_call("mcp_browseros_navigate_page", {"type": "url", "url": url})
        observed = _runtime_call("mcp_browseros_get_active_page", {})
        urls = {_canonical_https_url(value) for value in _url_fields(observed)}
        if urls != {_canonical_https_url(url)}:
            raise RuntimeError("browser URL unverified")

    def execute(self, action_id, inputs):
        if ACTION_EXECUTORS.get(action_id) != "browseros":
            raise PermissionError("executor/action mismatch")
        if action_id == "browser.open":
            self._navigate_verified(inputs["url"])
            return {"browser_url_matches": True}
        if action_id == "credential.change":
            self._navigate_verified(self.ACCOUNT_SECURITY_URLS[inputs["account"]])
            return {"credential_change_observed": True}
        if action_id == "message.send":
            payload = _runtime_call(
                "send_message",
                {
                    "action": "send",
                    "target": inputs["recipientID"],
                    "message": inputs["body"],
                },
            )
            if payload.get("success") is not True:
                raise RuntimeError("message delivery unverified")
            return {"message_delivery_observed": True}
        raise PermissionError("unsupported browser/messaging action")


class CuaAdapter:
    APP_NAMES = {
        "dev.zed.Zed": "Zed",
        "com.browseros.BrowserOS": "BrowserOS",
        "com.mitchellh.ghostty": "Ghostty",
    }

    def _capture(self, bundle_id):
        app = self.APP_NAMES[bundle_id]
        payload = _runtime_call(
            "computer_use",
            {"action": "capture", "mode": "ax", "app": app, "max_elements": 100},
        )
        elements = payload.get("elements")
        total = payload.get("total_elements")
        truncated = payload.get("truncated_elements", 0)
        if (
            payload.get("mode") != "ax"
            or payload.get("app") != app
            or not isinstance(elements, list)
            or len(elements) > 100
            or any(not _valid_ax_element(item) for item in elements)
            or len({item["index"] for item in elements}) != len(elements)
            or type(total) is not int
            or total < len(elements)
            or type(truncated) is not int
            or truncated < 0
            or truncated != total - len(elements)
            or len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            > 65536
        ):
            raise RuntimeError("AX target observation unverified")
        return payload

    def execute(self, action_id, inputs):
        if ACTION_EXECUTORS.get(action_id) != "cua":
            raise PermissionError("executor/action mismatch")
        bundle_id = inputs["bundleID"]
        app = self.APP_NAMES[bundle_id]
        if action_id == "cua.observe":
            capture = self._capture(bundle_id)
            if not capture["elements"]:
                raise RuntimeError("no AX element observed")
            return {
                "element_observed": True,
                "capture": {
                    "bundleID": bundle_id,
                    "app": app,
                    "elements": capture["elements"],
                    "totalElements": capture.get(
                        "total_elements", len(capture["elements"])
                    ),
                    "truncatedElements": capture.get("truncated_elements", 0),
                },
            }
        if action_id == "cua.focus":
            payload = _runtime_call(
                "computer_use",
                {"action": "focus_app", "app": app, "raise_window": False},
            )
            _require_action(payload, "focus_app")
            self._capture(bundle_id)
            return {"element_focused": True}
        if action_id in {"cua.click", "cua.type"}:
            capture = self._capture(bundle_id)
            if not any(
                item.get("index") == inputs["element"]
                for item in capture["elements"]
                if isinstance(item, dict)
            ):
                raise RuntimeError("requested AX element not observed")
            clicked = _runtime_call(
                "computer_use",
                {"action": "click", "app": app, "element": inputs["element"]},
            )
            _require_action(clicked, "click")
            if action_id == "cua.click":
                return {"element_clicked": True}
            written = _runtime_call(
                "computer_use",
                {
                    "action": "set_value",
                    "app": app,
                    "element": inputs["element"],
                    "value": inputs["text"],
                },
            )
            _require_action(written, "set_value")
            return {"text_entered": True}
        raise PermissionError("unsupported CUA action")


class TerminalAdapter:
    DIAGNOSTICS = {
        "disk_usage": "/bin/df -h",
        "process_list": "/bin/ps -axo pid,comm",
        "network_routes": "/usr/sbin/netstat -rn",
    }

    def execute(self, action_id, inputs):
        if ACTION_EXECUTORS.get(action_id) != "terminal":
            raise PermissionError("executor/action mismatch")
        if action_id == "terminal.diagnostic":
            command = self.DIAGNOSTICS[inputs["probe"]]
            postcondition = "diagnostic_reported"
        elif action_id == "shell.destructive":
            command = "/bin/rm -rf -- build"
            postcondition = "destructive_command_result_observed"
        elif action_id == "health.observe":
            command = "/usr/bin/uptime && /bin/df -h"
            postcondition = "health_report_complete"
        else:
            raise PermissionError("unsupported terminal action")
        payload = _runtime_call("terminal", {"command": command, "timeout": 30})
        if type(payload.get("exit_code")) is not int or payload["exit_code"] != 0:
            raise RuntimeError("terminal exit evidence missing or nonzero")
        if (
            action_id in {"terminal.diagnostic", "health.observe"}
            and not str(payload.get("output", "")).strip()
        ):
            raise RuntimeError("terminal observation output missing")
        return {postcondition: True}


class TypedFileAdapter:
    @staticmethod
    def _scoped(value):
        path = Path(value).expanduser().resolve()
        home = Path.home().resolve()
        if path != home and home not in path.parents:
            raise PermissionError("path outside user home")
        return path

    def execute(self, action_id, inputs):
        if ACTION_EXECUTORS.get(action_id) != "file":
            raise PermissionError("executor/action mismatch")
        if action_id == "file.reveal":
            path = self._scoped(inputs["path"])
            result = subprocess.run(["/usr/bin/open", "-R", str(path)], check=False)
            if not path.exists() or result.returncode != 0:
                raise RuntimeError("file reveal failed")
            return {"file_revealed": True}
        if action_id == "file.move":
            source = self._scoped(inputs["source"])
            destination = self._scoped(inputs["destination"])
            shutil.move(str(source), str(destination))
            if source.exists() or not destination.exists():
                raise RuntimeError("file move unverified")
            return {"move_verified": True}
        if action_id == "developer.digest":
            home = Path(os.environ["HERMES_HOME"])
            rows = TraceStore(home / "deskpilot-traces.db").successful()
            output = home / "reports/developer-digest.json"
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = output.with_suffix(".tmp")
            temporary.write_text(
                json.dumps({"window": inputs["window"], "calls": rows}, sort_keys=True)
                + "\n"
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, output)
            return {"digest_artifact_written": output.is_file()}
        raise PermissionError("unsupported file action")


class HammerspoonAdapter:
    def __init__(self, executor):
        self.executor = executor

    def execute(self, action_id, inputs):
        if ACTION_EXECUTORS.get(action_id) != "hammerspoon":
            raise PermissionError("executor/action mismatch")
        return dict(self.executor.execute(action_id, dict(inputs)).observed)


def default_adapters():
    request_dir = Path.home() / ".deskpilot/run/hammerspoon"
    return {
        "hammerspoon": HammerspoonAdapter(
            HammerspoonExecutor(SubprocessRunner(), request_dir)
        ),
        "browseros": BrowserMessagingAdapter(),
        "cua": CuaAdapter(),
        "terminal": TerminalAdapter(),
        "file": TypedFileAdapter(),
    }


def _process_running(name):
    def probe(_inputs):
        return (
            subprocess.run(
                ["/usr/bin/pgrep", "-x", name], capture_output=True, check=False
            ).returncode
            == 0
        )

    return probe


def _unix_socket(path):
    def probe(_inputs):
        try:
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(0.25)
                peer.connect(str(path))
            return True
        except OSError:
            return False

    return probe


def _tcp_ready(host, port):
    def probe(_inputs):
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            return False

    return probe


def build_environment_probes():
    home = Path.home().resolve()
    run = home / ".deskpilot/run"
    trace_db = (
        Path(os.environ.get("HERMES_HOME", home / ".deskpilot/hermes"))
        / "deskpilot-traces.db"
    )

    def one_path(inputs, key):
        try:
            return Path(str(inputs[key])).expanduser().resolve()
        except (KeyError, OSError):
            return None

    def paths(inputs):
        values = [inputs[key] for key in ("source", "destination") if key in inputs]
        try:
            return [Path(str(value)).expanduser().resolve() for value in values]
        except OSError:
            return []

    def accessibility(_inputs):
        result = subprocess.run(
            [
                "/usr/bin/osascript",
                "-e",
                'tell application "System Events" to return UI elements enabled',
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip().casefold() == "true"

    def local_ui(_inputs):
        lease = run / "ui-lease"
        try:
            return lease.is_file() and stat.S_IMODE(lease.stat().st_mode) == 0o600
        except OSError:
            return False

    def scoped(path):
        return path is not None and (path == home or home in path.parents)

    return {
        "accessibility": accessibility,
        "zed_running": _process_running("Zed"),
        "ghostty_running": _process_running("Ghostty"),
        "browseros_ready": lambda inputs: (
            _runtime_tool_ready(
                "mcp_browseros_navigate_page",
                {"type": "url", "url": "https://example.invalid"},
            )
            and _runtime_tool_ready("mcp_browseros_get_active_page", {})
            and _tcp_ready("127.0.0.1", 9239)(inputs)
        ),
        "cua_ready": lambda _inputs: _component_ready("cua"),
        "terminal_ready": lambda _inputs: shutil.which("zsh") is not None,
        "path_exists": lambda inputs: (
            (path := one_path(inputs, "path")) is not None and path.exists()
        ),
        "path_user_scoped": lambda inputs: scoped(one_path(inputs, "path")),
        "source_exists": lambda inputs: (
            (path := one_path(inputs, "source")) is not None and path.exists()
        ),
        "paths_user_scoped": lambda inputs: (
            bool(paths(inputs)) and all(scoped(path) for path in paths(inputs))
        ),
        "recipient_exact": lambda inputs: (
            bool(inputs.get("recipientID"))
            and inputs.get("recipientID")
            == inputs.get("confirmedRecipientID", inputs.get("recipientID"))
        ),
        "local_ui_present": local_ui,
        "health_probes_ready": lambda inputs: (
            _tcp_ready("127.0.0.1", 1234)(inputs)
            and _unix_socket(run / "policy.sock")(inputs)
        ),
        "trace_store_ready": lambda _inputs: (
            trace_db.parent.is_dir() and os.access(trace_db.parent, os.W_OK)
        ),
    }


def _component_ready(component):
    try:
        from deskpilot_hermes.status_server import component_ready
    except ImportError:
        return False
    return component_ready(component)


_lock = threading.Lock()
_installed_dispatcher = None


def install_deskpilot_runtime(environment, adapters=None):
    global _installed_dispatcher
    required = {
        "accessibility",
        "zed_running",
        "ghostty_running",
        "browseros_ready",
        "cua_ready",
        "terminal_ready",
        "path_exists",
        "path_user_scoped",
        "source_exists",
        "paths_user_scoped",
        "recipient_exact",
        "local_ui_present",
        "health_probes_ready",
        "trace_store_ready",
    }
    if not required <= set(environment):
        raise RuntimeError("DeskPilot environment probes incomplete")
    adapters = adapters or default_adapters()
    if set(adapters) != {"hammerspoon", "browseros", "cua", "terminal", "file"}:
        raise RuntimeError("DeskPilot executor adapters incomplete")
    with _lock:
        if _installed_dispatcher is None:
            _installed_dispatcher = DeskPilotToolDispatcher(
                ParentPolicyClient(), adapters, environment, wait_for_local_approval
            )
            set_tool_dispatcher(_installed_dispatcher)
        return _installed_dispatcher


def installed_dispatcher():
    if _installed_dispatcher is None:
        raise RuntimeError("DeskPilot runtime is not installed")
    return _installed_dispatcher
