# Contributing

Thanks for considering a contribution to `log-parser`. Keep changes small, tested, and aligned with the existing public API.

## Local checks

```bash
python -m pip install -e .
python -m pip install pytest pytest-cov ruff
ruff check .
pytest -q
```

## Contribution rules

- Add or update tests for behavior changes.
- Keep README examples in sync with the implementation.
- Keep runtime dependencies minimal and intentional.
- Prefer explicit errors over surprising coercions.
