from pathlib import Path
from runpy import run_path


def test_parent_and_hermes_are_distinct_regular_packages():
    import deskpilot
    import deskpilot_hermes

    parent_dir = Path(deskpilot.__file__).resolve().parent
    hermes_dir = Path(deskpilot_hermes.__file__).resolve().parent

    assert parent_dir != hermes_dir
    assert list(deskpilot.__path__) == [str(parent_dir)]
    assert list(deskpilot_hermes.__path__) == [str(hermes_dir)]
    assert (parent_dir / "__init__.py").is_file()
    assert (hermes_dir / "__init__.py").is_file()


def test_hermes_modules_do_not_live_under_parent_package_path():
    import deskpilot

    parent_dir = Path(next(iter(deskpilot.__path__))).resolve()
    for module in ("integration.py", "provenance.py", "policy.py"):
        assert not (parent_dir / module).exists()


def test_hermes_does_not_duplicate_parent_action_registry():
    from deskpilot.actions import ActionRegistry
    import deskpilot_hermes

    assert ActionRegistry.__module__ == "deskpilot.actions"
    assert not hasattr(deskpilot_hermes, "ActionRegistry")


def test_parent_wheel_prerequisite_has_an_actionable_collection_guard():
    test_dir = Path(__file__).resolve().parent
    readme = (test_dir / "README.md").read_text()
    guard = (test_dir / "conftest.py").read_text()
    install = (
        ".venv/bin/python -m pip install --no-deps --force-reinstall "
        "/private/tmp/deskpilot-parent-wheel/deskpilot-0.1.0-py3-none-any.whl"
    )
    assert install in readme
    assert run_path(str(test_dir / "conftest.py"))["_INSTALL"] == install
    assert 'find_spec("deskpilot")' in guard
