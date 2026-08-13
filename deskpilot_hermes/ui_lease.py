import json
import os
import stat
from pathlib import Path
from typing import Any

from deskpilot_hermes.validation import nonempty_string, validate_bounded_future


class LiveUILeaseReader:
    """Read the app-published private UI lease without creating new authority."""

    def __init__(self, path: str | Path | None = None, identity_verifier=None):
        self.path = (
            Path(path) if path is not None else Path.home() / ".deskpilot/run/ui-lease"
        )
        if identity_verifier is None:
            # Resolved from the same DESKPILOT_CONFIG the policy server reads, so
            # the reader and the server agree on one closed allowlist instead of
            # this side silently pinning a different identity. Falls back to the
            # production-only default when unset, never wider.
            from deskpilot.config import ui_identity_verifier

            identity_verifier = ui_identity_verifier()
        self.identity_verifier = identity_verifier

    def _validate_private_ancestors(self) -> None:
        boundary = Path.home() / ".deskpilot"
        try:
            self.path.relative_to(boundary)
        except ValueError:
            return
        current = self.path.parent
        while True:
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise PermissionError("UI lease ancestor must be a directory")
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise PermissionError("UI lease ancestor permissions denied")
            if current == boundary:
                return
            if boundary not in current.parents:
                raise PermissionError("UI lease ancestor escaped boundary")
            current = current.parent

    @staticmethod
    def _validate_record(value: Any) -> tuple[str, int]:
        if not isinstance(value, dict) or set(value) != {"uiLease", "pid", "expiresAt"}:
            raise ValueError("invalid UI lease record")
        lease = value["uiLease"]
        pid = value["pid"]
        if not nonempty_string(lease) or type(pid) is not int or pid <= 0:
            raise ValueError("invalid UI lease identity")
        validate_bounded_future(value["expiresAt"])
        return lease, pid

    def read(self) -> str:
        if not self.path.is_absolute():
            raise ValueError("absolute UI lease path required")
        self._validate_private_ancestors()
        metadata = self.path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise PermissionError("UI lease must be a regular file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PermissionError("UI lease owner or mode denied")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            opened = os.fstat(descriptor)
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            raise PermissionError("UI lease changed while opening")
        if len(raw) > 4096:
            raise ValueError("UI lease exceeds maximum size")
        value = json.loads(raw.decode("utf-8"))
        lease, pid = self._validate_record(value)
        os.kill(pid, 0)
        verifier = self.identity_verifier
        verified = verifier(pid) if callable(verifier) else verifier.verify(pid)
        if verified is not True:
            raise PermissionError("UI lease signing identity denied")
        return lease
