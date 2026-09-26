"""tests/conftest.py — Shared test helpers and pytest configuration.

Helpers defined here are importable as:
    from conftest import assert_chain_starts_at_entry, ...

Pytest adds the rootdir (and testpaths) to sys.path at collection time,
so ``conftest`` is importable without a package prefix.
"""
from __future__ import annotations

from t24.reach import ReachResult


def assert_chain_starts_at_entry(result: ReachResult, *, entry_function: str) -> None:
    """Assert the evidence chain is non-empty and starts at *entry_function*.

    Every evidence chain must start at an entry point (a Flask route,
    add_url_rule target, or ``<module>`` for module-level code).  The
    ``function`` field of the first hop must name that entry-point function.
    """
    assert result.evidence, f"Expected evidence for {result.target}, got []"
    first = result.evidence[0]
    assert first.function == entry_function, (
        f"First hop function must be {entry_function!r}, got {first.function!r}"
    )


def assert_no_module_level_in_methods(result: ReachResult) -> None:
    """Assert no hop in a method-call evidence chain is labelled '<module>'.

    ``'<module>'`` is only valid for genuine top-level (module-body) statements.
    A hop inside any class method must carry the qualified name ``'Class.method'``.
    """
    for hop in result.evidence:
        assert hop.function != "<module>", (
            f"Hop in evidence chain incorrectly labelled '<module>': {hop}"
        )
