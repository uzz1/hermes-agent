from pathlib import Path


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
