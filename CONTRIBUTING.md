# Contributing

Thanks for contributing to LuaNilGuard.

## Development Setup

1. Use Python 3.12 or newer.
2. Clone the repository.
3. Create and activate a virtual environment.
4. Install the project in editable mode:

```sh
pip install -e .
```

## Running Tests

Run the full test suite before opening a pull request:

```sh
pytest -q
```

If you are touching a narrow area, run the focused tests first, then finish with the full suite.

## Pull Request Guidelines

- Keep changes scoped to one clear purpose.
- Preserve the precision-first design of the review engine.
- Prefer bounded, deterministic analysis over broad heuristic expansion.
- Add or update tests for behavior changes.
- Update user-facing docs when commands, configuration, or expected workflow changes.

## Code Style

- Follow existing project style and naming.
- Keep changes readable and explicit.
- Avoid destructive git operations in shared branches.

## Reporting Issues

When filing a bug, include:

- the command you ran
- the relevant Lua snippet or repository layout
- the observed result
- the expected result
- backend details, if an LLM backend was used

For feature requests, describe the real code pattern or workflow that is blocked today.
