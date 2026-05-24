# log-parser quality bar

This repository is part of a public portfolio, so the bar is practical correctness, clear documentation, and reproducible checks.

## Required checks

- `ruff check .` must pass with no ignored failures.
- `pytest -q` must pass.
- Packaging metadata must install the same source tree that tests exercise.
- Public behavior changes must include happy-path, edge-case, and error tests.

## Release checklist

- Run the required checks locally.
- Confirm GitHub Actions is green on the default branch.
- Confirm Dependabot and secret scanning have no open alerts.
- Confirm the README still describes the actual API and scope.
