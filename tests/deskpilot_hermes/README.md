# DeskPilot parent integration prerequisite

This focused suite intentionally tests package isolation against the pinned
parent DeskPilot `0.1.0` wheel. It does not declare or download a remote test
dependency. Build the parent checkout at commit
`9d2c24f17514271e0bed599ff5dd567e1b37400e`, then install that local artifact:

```sh
uv build --wheel --out-dir /private/tmp/deskpilot-parent-wheel /Users/uzairebrahim/Developer/deskpilot/.worktrees/deskpilot-v1
.venv/bin/python -m pip install --no-deps --force-reinstall /private/tmp/deskpilot-parent-wheel/deskpilot-0.1.0-py3-none-any.whl
```

Run the suite only after the pinned parent package is importable.
