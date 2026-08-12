# DeskPilot parent integration prerequisite

This focused suite intentionally tests package isolation against the pinned
parent DeskPilot `0.1.0` package. It does not declare or download a remote test
dependency. Check out parent commit
`9d2c24f17514271e0bed599ff5dd567e1b37400e`, then install that local artifact:

```sh
.venv/bin/python -m pip install --no-deps --force-reinstall <deskpilot-parent-worktree>
```

Run the suite only after the pinned parent package is importable. CI must install
the pinned parent artifact before collecting these tests.
