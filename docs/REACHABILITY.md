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

## Class method model

Each class method is stored as a graph node with the **qualified name**
`ClassName.method_name` (e.g. `Loader.load`, `S._p`).  This separates
method bodies from module-level code.

**Key rules:**

- A class body runs at import time, but **method bodies do not**.
  Only a method body whose qualified node is reachable from an entry point
  contributes to a call chain.
- An unused class — never instantiated, never called — produces no reachable
  nodes even if its methods reference vulnerable symbols.
- `self.method()` inside a method is an unresolved method call and is
  over-approximated exactly like `obj.method()` (see below).

**Example:**
```python
class Loader:
    def load(self, raw): return yaml.full_load(raw)

@app.route("/upload")
def upload():
    return Loader().load(raw)
```
Evidence chain:
```
app.py:14  function="upload"      call="Loader().load"
app.py:9   function="Loader.load" call="yaml.full_load"
```

**Unused class — NOT reached:**
```python
class Unused:
    def load(self, raw): return yaml.full_load(raw)  # never called

@app.route("/ping")
def ping():
    return "pong"  # yaml never reached
```

---

## What is over-approximated (sound, may produce false positives)

### Method calls on unresolved objects (`obj.method()`, `self.method()`)

When a call takes the form `obj.method(...)` and `obj` cannot be resolved to
a known import alias (e.g. it is a locally-constructed instance, the parameter
`self`, or any other unresolved local name), the engine adds graph edges to
**every product-defined function whose short name matches `method`**,
regardless of class.  This includes `self.method()` calls inside class bodies.

**Example:**
```python
class S:
    def go(self):
        self._p()     # unresolved — over-approx to all S._p / other ._p methods

    def _p(self):
        yaml.full_load("x: 1")

@app.route("/")
def index():
    S().go()
```

The engine connects `index → S.go → S._p → yaml.full_load` via the
over-approximation, producing a correct 3-hop evidence chain.

**False-positive scenario:** if multiple classes define a method with the same
short name, all of them get edges — some will be spurious.  The verdict remains
sound: if any of those paths reaches the vulnerable target, `affected` is correct.

This over-approximation is implemented in
[`t24/reach_graph.py`](../t24/reach_graph.py) `build_graph()` and
[`t24/reach_parse.py`](../t24/reach_parse.py) `_receiver_is_known_import()`.

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
| Module object passed as value | e.g. `use(yaml)` — any `.attr` access later is opaque |

**Module-object-as-value example:**
```python
def use(m): return m.full_load(raw)   # m is an opaque parameter

@app.route("/upload")
def upload():
    use(yaml)   # yaml module passed by value — uncertain
```
The bare module name `yaml` (a known target module) is passed as a positional
argument.  All subsequent attribute accesses on the parameter `m` are invisible
to static analysis, so the engine sets `uncertain=True`.

**Note:** `getattr(obj, "literal_name")` with a string constant is NOT flagged
as uncertain (the attribute name is known at parse time).  Only dynamic
expressions trigger uncertainty.

---

## Products outside the working directory

When `scan()` is called with a `product_root` that is not under the current
working directory (e.g. a path in `/tmp` while the repo is the CWD), the
engine uses the product root's parent as the base for relative evidence paths.
This prevents `ValueError` from `Path.relative_to()` and always produces
forward-slash evidence paths regardless of OS.

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
  (or relative to the product root's parent if the product is outside CWD)
- `line`: 1-based line number of the call expression
- `function`: enclosing function name; `"<module>"` for genuine module-level
  statements; `"ClassName.method"` for class methods; `"<template>"` for
  Jinja2 template hops
- `call`: the call expression as printed by `ast.unparse`

### Evidence chain invariants

1. The first hop's `function` is always an entry-point function name (a Flask
   route name, `add_url_rule` target, or `"<module>"`).
2. `"<module>"` appears **only** when the call is a genuine top-level
   statement — never inside a class body or function body.
3. Class method hops carry the qualified name `"ClassName.method"`, not the
   bare method name or `"<module>"`.
