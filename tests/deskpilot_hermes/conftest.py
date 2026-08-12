from importlib.util import find_spec

import pytest


_INSTALL = (
    ".venv/bin/python -m pip install --no-deps --force-reinstall "
    "/private/tmp/deskpilot-parent-wheel/deskpilot-0.1.0-py3-none-any.whl"
)


def pytest_configure() -> None:
    if find_spec("deskpilot") is None:
        pytest.exit(
            "DeskPilot Hermes integration tests require the pinned parent wheel. "
            f"Install it locally with: {_INSTALL}",
            returncode=4,
        )
