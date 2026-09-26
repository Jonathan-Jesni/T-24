# T-24 Reachability Analysis — Known Capabilities and Limits

This document describes what the T-24 static reachability engine resolves,
what it over-approximates (sound but imprecise), and what it cannot determine
(triggers `uncertain=True`).

**Design principle:** Soundness over completeness. A false negative (reporting
"not reached" when the target IS reachable) is the one failure T-24 must never
produce. False positives (extra `under_investigation` verdicts) are acceptable.

---

## What is resolved precisely

| Pattern | Example | Resolved as |
|---------|---------|-------------|
| Direct call | `yaml.full_load(data)` | Exact hop |
| Aliased module import | `import yaml as y; y.full_load(data)` | Exact hop |
| From-import | `from yaml import full_load; full_load(data)` | Exact hop |
| From-import with alias | `from yaml import full_load as fl; fl(data)` | Exact hop |
| Attribute chain | `from PIL import ImageMath; ImageMath.eval(env=...)` | Exact hop |
| Keyword-arg reference | `yaml.load(data, Loader=yaml.FullLoader)` | Reference hop |
| Positional-arg reference (callback) | `run(yaml.full_load, data)` | Reference hop |
| Flask route decorator | `@app.route(...)`, `@app.get(...)`, etc. | Entry point |
| `add_url_rule` registration | `app.add_url_rule("/a", view_func=a)` | Entry point |
| Module-level statements | `CFG = yaml.full_load(open("c.yml"))` | Entry point `<module>` |
| `if __name__ == "__main__"` blocks | — | Entry point `<module>` |
| Relative imports | `from .helpers import parse` in `svc/loader.py` | Resolved via dotted path |
| Absolute package imports | `from svc.loader import load` | Resolved to product module |
| Cross-file call graph | `app.py → config.py → yaml.full_load` | Multi-hop evidence |
| Template filter | `{{ attrs \| xmlattr }}` in a rendered template | Template hop |

---

## What is over-approximated (sound, may produce false positives)

### Method calls on unresolved objects

When a call takes the form `obj.method(...)` and `obj` cannot be resolved to
a known import alias (e.g. it is a locally-constructed instance), the engine
adds graph edges to **every product-defined function named `method`**,
regardless of class.

**Example:**
```python
class Loader:
    def load(self, raw): return yaml.full_load(raw)

Loader().load(x)   # obj is an unresolved local instance
```

The engine connects `upload → load` (the only product function named `load`),
so `yaml.full_load` is correctly reached.

**False-positive scenario:** if the product contains many classes with a method
named `load`, all of them get edges — some will be spurious. The verdict remains
sound: if any of those paths reaches the vulnerable target, `affected` is correct.

This over-approximation is documented in code at
[`t24/reach_graph.py`](../t24/reach_graph.py) in `build_graph()`.

---

## What triggers `uncertain=True`

When the engine encounters any of the following patterns, it cannot statically
determine whether the target is reachable. `ReachResult.uncertain` is set to
`True` and `ReachResult.uncertain_sites` lists each occurrence.

The verdict engine must treat `uncertain=True` as `under_investigation`.

| Pattern | Reason |
|---------|--------|
| `getattr(obj, dynamic_expr)` | Attribute name is not a compile-time constant |
| `importlib.import_module("yaml")` | Module loaded dynamically; imports not tracked |
| `__import__("yaml")` | Dynamic import |
| `from yaml import *` | All names from module pulled into scope; cannot track |
| Module object passed as value | e.g. `fn(yaml)` — any attribute access later is opaque |

**Note:** `getattr(obj, "literal_name")` with a string constant is NOT flagged
as uncertain (the attribute name is known at parse time). Only dynamic expressions
trigger uncertainty.

---

## Known limitations (not currently handled)

| Limitation | Effect | Planned fix |
|------------|--------|-------------|
| Class inheritance | A subclass overriding a method is not tracked | Manual `--entry-points` |
| Decorators that wrap functions | `@app.route` is detected; custom wrapping decorators are not | Explicit entry points |
| `exec()` / `eval()` with string code | Cannot be analysed statically | Flagged as uncertain in future |
| Conditional imports (`if sys.version_info >= ...`) | Both branches are parsed, so imports from both are included | Acceptable (over-approximation) |
| Type annotations as import-only usage | `def f(x: yaml.YAMLObject)` is not a call | Not a vulnerability vector; by design |
| External library re-exports | If `pandas` re-exports `yaml.full_load`, the alias is not tracked | Scope: direct dependencies only |
| Inter-process calls (subprocess, socket) | Not tracked | Out of scope |
| C extensions | Only Python source is parsed | By design |

---

## Coverage and the `not_affected` gate

`not_affected / vulnerable_code_not_in_execute_path` is emitted **only when**:

1. `files_parsed == files_found` (every `.py` file in the product parsed successfully)
2. `uncertain == False` (no dynamic-access patterns found)
3. No evidence path from any entry point to any vulnerable symbol was found

If any file fails to parse or any dynamic pattern is detected, the verdict is
`under_investigation`, not `not_affected`.

---

## Evidence path format

Each hop in `evidence` is:
```json
{"file": "demo_product/app.py", "line": 14, "function": "upload_config", "call": "config.load_settings"}
```

- `file`: forward-slash path relative to the working directory at scan time
- `line`: 1-based line number of the call expression
- `function`: enclosing function name, or `"<module>"` for module-level code
- `call`: the call expression as printed by `ast.unparse`
