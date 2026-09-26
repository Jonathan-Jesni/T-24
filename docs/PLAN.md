# T-24 — Project Plan

> "Prove whether you're affected before the CRA clock runs out."
> IBM Bob 2.0 Hackathon — Theme: Improve a developer workflow

---

## 0. Problem and Goal

Since 11 Sep 2026, EU Cyber Resilience Act Article 14 requires:

| Deadline | Action |
|----------|--------|
| 24 h | ENISA early warning |
| 72 h | ENISA notification |
| 14 d | ENISA final report |

Penalty: up to EUR 15 M or 2.5 % of worldwide turnover.

When a dependency advisory drops, developers spend hours answering "are we even
affected?" — most alerts cover code paths the product never calls. T-24 automates
that triage in a reproducible, auditable way and, when a finding is confirmed
affected and actively exploited, drafts the required ENISA reports automatically.

---

## 1. Verified Advisory Facts

> Source: GitHub Advisory Database (CC-BY-4.0). Fetched via
> `curl -s https://api.github.com/advisories/<GHSA_ID>`. Used in demo_product/.

| CVE | GHSA | Package | Installed | Affected range | Fixed | Vulnerable symbol | Expected verdict |
|-----|------|---------|-----------|----------------|-------|-------------------|-----------------|
| CVE-2020-14343 | GHSA-8q59-q68h-6hv4 | PyYAML | 5.3.1 | `< 5.4` | 5.4 | `full_load`, `FullLoader` | AFFECTED |
| CVE-2023-50447 | GHSA-3f63-hfp8-52jq | Pillow | 9.5.0 | `< 10.2.0` | 10.2.0 | `PIL.ImageMath.eval` | NOT_AFFECTED (not in execute path) |
| CVE-2024-22195 | GHSA-h5c8-rqwp-cp95 | jinja2 | 3.1.2 | `< 3.1.3` | 3.1.3 | `xmlattr` | NOT_AFFECTED (not in execute path) |
| CVE-2023-32681 | GHSA-j8r2-6x86-q33q | requests | 2.30.0 | `>= 2.3.0, < 2.31.0` | 2.31.0 | _(none; precondition: proxy config)_ | UNDER_INVESTIGATION |

---

## 2. Repository Layout

```
T-24/
├── t24/                    # Python package — owned by this engineer
│   ├── __init__.py
│   ├── __main__.py         # python -m t24 entry-point
│   ├── cli.py              # Typer CLI wiring
│   ├── advisory.py         # LLM advisory reader + verbatim-symbol check
│   ├── inventory.py        # Deterministic version-range checker
│   ├── reach.py            # AST import+call-graph reachability
│   ├── verdict.py          # Deterministic verdict engine (OpenVEX statuses)
│   ├── clock.py            # CRA 24h/72h/14d deadline calculator
│   ├── vex.py              # OpenVEX 0.2.0 JSON writer
│   └── report.py           # ENISA draft report renderer (Markdown)
├── tests/                  # pytest suite — owned by this engineer
│   ├── conftest.py
│   ├── test_advisory.py
│   ├── test_inventory.py
│   ├── test_reach.py
│   ├── test_verdict.py
│   ├── test_clock.py
│   ├── test_vex.py
│   ├── test_report.py
│   └── test_cli.py
├── demo_product/           # Tiny Flask app — owned by this engineer
│   ├── requirements.txt    # Pinned to vulnerable versions
│   └── app.py              # Flask routes that exercise the vulnerable paths
├── advisories/             # Advisory markdown files — owned by this engineer
│   ├── CVE-2020-14343.md
│   ├── CVE-2023-50447.md
│   ├── CVE-2024-22195.md
│   └── CVE-2023-32681.md
├── cache/                  # Cached LLM extractions (JSON) — offline demo
├── out/                    # Generated outputs (gitignored)
│   ├── vex.json
│   ├── dossier.json
│   └── drafts/
├── .bob/                   # Bob custom mode + skill — owned by this engineer
│   ├── modes/
│   │   └── t24-mode.yaml
│   └── skills/
│       └── t24-triage/
│           └── SKILL.md
├── dossier/                # Web UI — owned by teammate; NEVER edit
├── docs/
│   ├── PLAN.md             # This file
│   ├── DATA_CONTRACT.md
│   └── DATA_SOURCES.md
├── AGENTS.md
├── README.md
├── .bobignore
├── pyproject.toml
└── vercel.json             # Owned by teammate; do not edit
```

---

## 3. Architecture

```
advisories/*.md
      │
      ▼
[advisory.py]  ─── LLM (watsonx / Fireworks / cached) ──► extracted symbols
      │                                                      verbatim check ✓
      ▼
[inventory.py] ─── packaging.specifiers ──► version in range? (bool)
      │
      ▼
[reach.py]     ─── Python AST (ast module) ──► call graph ──► evidence path
      │              entry points from CLI args
      ▼
[verdict.py]   ─── pure deterministic logic ──► OpenVEX status + justification
      │              LLM NEVER touches verdict
      ▼
[clock.py]     ─── datetime arithmetic ──► 24h/72h/14d deadlines (if affected+exploited)
      │
      ├──► [vex.py]    ──► out/vex.json       (OpenVEX 0.2.0)
      ├──► [report.py] ──► out/drafts/*.md    (ENISA Markdown drafts)
      └──► [cli.py]    ──► out/dossier.json   (DATA_CONTRACT shape)
```

### Key design invariants

1. **The LLM only extracts symbols.** It never sets, suggests, or overrides the verdict.
2. **Verbatim symbol check.** Every symbol returned by the LLM is dropped unless it appears
   character-for-character in the advisory text. This is a deterministic post-extraction filter.
3. **not_affected requires 100 % parse coverage.** `vulnerable_code_not_in_execute_path` is
   only emitted when `files_parsed == files_found`.
4. **Preconditions block not_affected.** Any advisory that contains a runtime precondition
   that static analysis cannot prove (e.g., proxy configuration) yields `under_investigation`.
5. **Evidence is file:line hops.** Every hop in the call graph carries a file path and line
   number; the report renderer cites them directly.

---

## 4. Module Specifications

### 4.1 `t24/advisory.py`

**Purpose:** Read an advisory markdown file, call the LLM, return a structured
`AdvisoryExtraction` dataclass.

**Key responsibilities:**
- Load advisory text from `advisories/<CVE>.md`
- Build a prompt asking the LLM for: package, affected_range, fixed_version,
  symbols (list), preconditions (list)
- Post-extraction: drop any symbol not found verbatim in the advisory text
  (case-sensitive substring check)
- Cache result to `cache/<CVE>.json`; load from cache if present (enables offline demo)
- Provider selection: try watsonx.ai (ibm-granite/granite-3-3-8b-instruct or similar),
  fallback to Fireworks

**Dataclass:**
```python
@dataclass
class AdvisoryExtraction:
    cve: str
    package: str
    affected_range: str
    fixed_version: str
    symbols: list[str]          # verbatim-checked
    preconditions: list[str]    # e.g. ["proxies must be configured"]
    advisory_source: str        # URL from SOURCE line in markdown
    raw_advisory_text: str      # kept for evidence citation
```

**Constraints:** < 300 lines. No network calls in tests (use cache fixtures).

---

### 4.2 `t24/inventory.py`

**Purpose:** Parse `requirements.txt`, resolve installed versions, check each
package version against the extracted affected range.

**Key responsibilities:**
- Parse `requirements.txt` with `packaging.requirements`
- Normalize package names (PEP 503 canonical form)
- Use `packaging.specifiers.SpecifierSet` to test membership
- Return `VersionCheck` dataclass per package

**Dataclass:**
```python
@dataclass
class VersionCheck:
    package: str
    installed: str
    affected_range: str
    in_range: bool
```

**Constraints:** Pure stdlib + `packaging`. No network.

---

### 4.3 `t24/reach.py`

**Purpose:** Build a Python AST import+call graph over a project directory and
determine whether a set of vulnerable symbols is reachable from declared entry points.

**Key responsibilities:**
- Walk `*.py` files under the product directory
- Parse each file with `ast.parse`; record parse failures
- Build an import map: `module_alias → real_module` handling:
  - `import yaml` → `yaml`
  - `import yaml as y` → maps `y` → `yaml`
  - `from yaml import full_load` → `full_load` in local scope
  - `from yaml import full_load as fl` → maps `fl` → `yaml.full_load`
  - Attribute chains: `yaml.full_load(...)` resolves via import map
- Build a call graph: function → set of (callee_name, file, line)
- BFS/DFS from entry points to find evidence path to each vulnerable symbol
- Track `files_found` and `files_parsed` for coverage

**Dataclass:**
```python
@dataclass
class EvidenceHop:
    file: str
    line: int
    function: str
    call: str

@dataclass
class ReachResult:
    symbol: str
    reachable: bool
    evidence: list[EvidenceHop]
    files_found: int
    files_parsed: int
```

**Constraints:** Uses only `ast` (stdlib). No network. < 300 lines.

---

### 4.4 `t24/verdict.py`

**Purpose:** Apply deterministic verdict logic. The LLM never touches this.

**Decision tree (exact):**

```
if not version_check.in_range:
    → status=not_affected, justification=vulnerable_code_not_present

elif version_check.in_range AND symbols extracted AND any symbol reachable:
    → status=affected, justification=null, evidence=<hop list>

elif version_check.in_range AND symbols extracted
     AND none reachable AND coverage==100% AND no preconditions:
    → status=not_affected, justification=vulnerable_code_not_in_execute_path

elif version_check.in_range AND preconditions exist (unprovable statically):
    → status=under_investigation

else:  # no symbols named, or parse failures, or partial coverage
    → status=under_investigation
```

**Output:**
```python
@dataclass
class VerdictResult:
    cve: str
    status: Literal["affected", "not_affected", "under_investigation", "fixed"]
    justification: str | None
    evidence: list[EvidenceHop]
    reason: str           # human-readable one-liner
```

**Constraints:** Zero LLM calls. Pure Python logic. < 300 lines.

---

### 4.5 `t24/clock.py`

**Purpose:** Compute CRA Article 14 report deadlines and return structured clock data.

**Key responsibilities:**
- Accept `aware_at: datetime` (ISO 8601, timezone-aware)
- Compute:
  - `early_warning_due = aware_at + 24h`
  - `notification_due = aware_at + 72h`
  - `final_report_due = aware_at + 14d`
- Return `CRAClock` dataclass
- Only invoked when finding is `affected` AND `--actively-exploited` flag is set

**Dataclass:**
```python
@dataclass
class CRAClock:
    cve: str
    aware_at: datetime
    early_warning_due: datetime
    notification_due: datetime
    final_report_due: datetime
```

**Constraints:** stdlib `datetime` only. No network.

---

### 4.6 `t24/vex.py`

**Purpose:** Serialize findings to OpenVEX 0.2.0 JSON format.

**Key responsibilities:**
- Build an OpenVEX document with `@context`, `@id`, `timestamp`,
  `author`, `tooling`, `statements` array
- Each statement: `vulnerability.name`, `products`, `status`,
  `justification` (when not_affected), `impact_statement`
- Write to `out/vex.json`

**Constraints:** `json` stdlib only. < 300 lines.

---

### 4.7 `t24/report.py`

**Purpose:** Render ENISA early warning and notification drafts as Markdown.

**Key responsibilities:**
- Template for early warning (Art. 14 §1): product, vulnerability ID, date,
  preliminary description, current status
- Template for notification (Art. 14 §2): adds impact assessment,
  actions taken, cross-references
- Every factual claim cites `file:line` or an advisory line number
- Write to `out/drafts/early_warning_<CVE>.md` and `out/drafts/notification_<CVE>.md`

**Constraints:** No LLM calls in rendering. Templates use Python f-strings or
`string.Template`. < 300 lines.

---

### 4.8 `t24/cli.py` + `t24/__main__.py`

**Purpose:** Typer-based CLI that wires all modules together and writes outputs.

**CLI signature:**
```
t24 scan \
  --product <path>          # path to product directory
  --advisories <path>       # path to advisories directory (default: ./advisories)
  --entry-points <list>     # comma-separated module:function or file:function
  --actively-exploited <CVE>=<ISO8601>  # can repeat; sets aware_at for clock
  --out <path>              # output directory (default: ./out)
  --no-cache                # bypass LLM cache
```

**Output contract:** writes `out/vex.json` and `out/dossier.json` per
`docs/DATA_CONTRACT.md`, and `out/drafts/*.md` when due.

**`__main__.py`:** single line — `from t24.cli import app; app()` so
`python -m t24` works.

---

## 5. Demo Product

`demo_product/` — a minimal Flask label-printer service split across two files
to exercise cross-file evidence chains:

| File | Route / function | Behaviour | Reason for expected verdict |
|------|-----------------|-----------|----------------------------|
| `app.py` | `POST /upload-config` | calls `config.load_settings(request.data)` | Two-file hop: app → config → `yaml.full_load` |
| `config.py` | `load_settings(raw)` | calls `yaml.full_load(raw)` | Vulnerable call site |
| `app.py` | `POST /thumbnail` | `PIL.Image.open(...).thumbnail(...)` | Pillow used, `ImageMath.eval` never called |
| `app.py` | `GET /label/<id>` | `render_template("label.html", ...)` | Jinja2 used; `xmlattr` never in template |
| `app.py` | `POST /webhook` | `requests.post(url, json=...)` — no `proxies=` | Proxy precondition not provable statically |

`demo_product/requirements.txt`:
```
Flask==2.3.0
PyYAML==5.3.1
Pillow==9.5.0
Jinja2==3.1.2
requests==2.30.0
```

Entry-point detection: Flask route functions (decorated with `*.route`, `*.get`,
`*.post`, etc.) plus any module-level code under `if __name__ == "__main__"`.
`--entry-points file:function` overrides auto-detection.

---

## 6. Advisory Files

Each file in `advisories/` is Markdown with at minimum:

```markdown
# <CVE> — <Title>

SOURCE: <GitHub Advisory Database URL>

## Summary
...advisory text verbatim or paraphrased...

## Affected Versions
...

## Vulnerable Symbols
...
```

The `SOURCE:` line is parsed by `advisory.py` to populate `advisory_source`.

---

## 6a. Decisions

Answers to design questions; these govern implementation.

### D-1 Entry Points
Auto-detect Flask route functions: any function decorated with an expression
matching `*.route(...)`, `*.get(...)`, `*.post(...)` (or put/delete/patch).
Also include module-level code executed under `if __name__ == "__main__"`.
`--entry-points file:function` (repeatable) overrides auto-detection entirely.

### D-2 Pillow Evidence
`evidence` is `[]` for the Pillow finding because no call path from any entry
point reaches `PIL.ImageMath.eval`. The `reason` field reads:
> "Pillow is used (Image.thumbnail) but no path from any entry point reaches
> ImageMath.eval."

### D-3 Multiple Affected+Exploited CVEs
`clock` remains a single object. When multiple findings are `affected` and
actively exploited, use the one with the **earliest `aware_at`**. List the
other CVE IDs in the `reason` field of that clock object.

### D-4 Bob Mode Permissions
Apply **both** layers of defence:
1. The custom mode's `editFileRegex` (or equivalent permission field) is set to
   a regex that excludes `dossier/.*` and `vercel\.json` at the tool level —
   the agent cannot physically edit those files while in the mode.
2. [`AGENTS.md`](../AGENTS.md) Rule 1 states the same boundary in plain language
   for any agent that reads it.

---

## 7. Bob Integration

### Custom Mode — `t24-mode`

Defined in `.bob/modes/t24-mode.yaml`. Gives the agent:
- Read access to `t24/`, `tests/`, `advisories/`, `demo_product/`, `docs/`
- Write access to the same (never `dossier/`)
- `editFileRegex` excludes `dossier/.*` and `vercel\.json`
- System prompt reminding it of the deterministic verdict rule and DATA_CONTRACT

### Skill — `t24-triage`

Defined in `.bob/skills/t24-triage/SKILL.md`. A reference card for:
- Running the scan: `python -m t24 scan ...`
- Interpreting dossier.json
- Adding a new advisory
- Adding a new demo product route

---

## 8. Test Plan

All tests use `pytest`. No test makes a network call. LLM calls are mocked via
`unittest.mock` or pre-populated `cache/` fixtures.

| Test file | What it covers |
|-----------|---------------|
| `test_advisory.py` | Cache hit returns correct extraction; verbatim-symbol filter drops fabricated symbols; missing SOURCE line raises |
| `test_inventory.py` | In-range and out-of-range for each demo CVE; name normalisation (PyYAML vs pyyaml) |
| `test_reach.py` | yaml.full_load reachable from upload_config; PIL.ImageMath.eval not reachable; aliased import resolved; 100% parse coverage for demo_product |
| `test_verdict.py` | All four decision-tree paths; not_affected blocked when coverage < 100% |
| `test_clock.py` | Correct 24h/72h/14d arithmetic; timezone-aware input |
| `test_vex.py` | Output is valid JSON; contains required OpenVEX 0.2.0 keys |
| `test_report.py` | Draft contains product name, CVE, deadlines; evidence file:line appears |
| `test_cli.py` | End-to-end against demo_product with cached extractions; dossier.json matches DATA_CONTRACT shape |

**Order of implementation (TDD — tests first per module):**

1. `inventory.py` + `test_inventory.py` — no dependencies, verifiable immediately
2. `reach.py` + `test_reach.py` — depends only on stdlib ast
3. `advisory.py` + `test_advisory.py` — LLM path mocked; cache path real
4. `verdict.py` + `test_verdict.py` — composes previous modules
5. `clock.py` + `test_clock.py` — standalone datetime logic
6. `vex.py` + `test_vex.py` — serialization
7. `report.py` + `test_report.py` — template rendering
8. `cli.py` + `__main__.py` + `test_cli.py` — integration
9. `demo_product/` — Flask app wired to trigger the expected verdicts
10. `advisories/` — four advisory markdown files
11. `cache/` — pre-populated JSON for offline demo
12. `.bob/` — custom mode + skill
13. `pyproject.toml` — packaging + pytest config

---

## 9. Sub-Tasks

### ST-01 — Project scaffold and pyproject.toml
**Status:** [ ] pending

**Intent:** Establish the installable package structure, dependencies, and pytest config
so every subsequent module has a working import environment.

**Expected outcomes:**
- `pyproject.toml` with `[project]` metadata, `dependencies` (typer, packaging,
  requests, ibm-watsonx-ai), `[project.scripts] t24 = "t24.cli:app"`,
  `[tool.pytest.ini_options]`
- `t24/__init__.py`, `t24/__main__.py`
- `tests/conftest.py` with shared fixtures (demo_product path, advisory path,
  cache path)
- `out/`, `cache/` directories in `.gitignore` (or just `.bobignore`)

**Todo:**
- [ ] Write `pyproject.toml`
- [ ] Write `t24/__init__.py` (empty or version string)
- [ ] Write `t24/__main__.py`
- [ ] Write `tests/conftest.py`
- [ ] Verify `python -m pytest --collect-only` succeeds with zero tests collected
      (no errors)

---

### ST-02 — Inventory module
**Status:** [ ] pending

**Intent:** Deterministically check whether an installed version falls in an
advisory's affected range.

**Expected outcomes:** `test_inventory.py` passes for all four demo CVEs.

**Todo:**
- [ ] Write `tests/test_inventory.py` first
- [ ] Write `t24/inventory.py`
- [ ] Run `pytest tests/test_inventory.py`

---

### ST-03 — Reachability module
**Status:** [ ] pending

**Intent:** Build an AST call graph and return evidence paths.

**Expected outcomes:** `test_reach.py` passes; yaml.full_load reachable,
PIL.ImageMath.eval not reachable, xmlattr not reachable.

**Todo:**
- [ ] Write `demo_product/app.py` (needed as fixture)
- [ ] Write `demo_product/requirements.txt`
- [ ] Write `tests/test_reach.py` first
- [ ] Write `t24/reach.py`
- [ ] Run `pytest tests/test_reach.py`

---

### ST-04 — Advisory reader module
**Status:** [ ] pending

**Intent:** Extract structured fields from advisory text via LLM, with verbatim
symbol check and cache.

**Expected outcomes:** `test_advisory.py` passes; fabricated symbol dropped; cache
hit bypasses LLM; all four advisory markdown files in `advisories/`.

**Todo:**
- [ ] Write `advisories/CVE-2020-14343.md`
- [ ] Write `advisories/CVE-2023-50447.md`
- [ ] Write `advisories/CVE-2024-22195.md`
- [ ] Write `advisories/CVE-2023-32681.md`
- [ ] Write `cache/` JSON fixtures for offline demo
- [ ] Write `tests/test_advisory.py` first (mock LLM calls)
- [ ] Write `t24/advisory.py`
- [ ] Run `pytest tests/test_advisory.py`

---

### ST-05 — Verdict engine
**Status:** [ ] pending

**Intent:** Compose inventory + reach results into deterministic OpenVEX status.

**Expected outcomes:** All four demo CVE verdicts match expectations in section 2.

**Todo:**
- [ ] Write `tests/test_verdict.py` first
- [ ] Write `t24/verdict.py`
- [ ] Run `pytest tests/test_verdict.py`

---

### ST-06 — CRA clock module
**Status:** [ ] pending

**Intent:** Compute Art. 14 deadlines when a finding is affected and actively exploited.

**Expected outcomes:** `test_clock.py` passes; correct UTC arithmetic.

**Todo:**
- [ ] Write `tests/test_clock.py` first
- [ ] Write `t24/clock.py`
- [ ] Run `pytest tests/test_clock.py`

---

### ST-07 — OpenVEX writer
**Status:** [ ] pending

**Intent:** Serialize all findings to OpenVEX 0.2.0 JSON.

**Expected outcomes:** `out/vex.json` is valid JSON with required keys; `test_vex.py` passes.

**Todo:**
- [ ] Write `tests/test_vex.py` first
- [ ] Write `t24/vex.py`
- [ ] Run `pytest tests/test_vex.py`

---

### ST-08 — ENISA report renderer
**Status:** [ ] pending

**Intent:** Produce Art. 14 early warning and notification drafts in Markdown.

**Expected outcomes:** `out/drafts/early_warning_CVE-2020-14343.md` and
`out/drafts/notification_CVE-2020-14343.md` contain required fields; all
evidence citations include file:line.

**Todo:**
- [ ] Write `tests/test_report.py` first
- [ ] Write `t24/report.py`
- [ ] Run `pytest tests/test_report.py`

---

### ST-09 — CLI and end-to-end integration
**Status:** [ ] pending

**Intent:** Wire all modules via Typer CLI; produce `out/dossier.json` matching
DATA_CONTRACT exactly.

**Expected outcomes:** `python -m t24 scan --product demo_product --no-cache`
(with cache) produces correct dossier.json; `test_cli.py` passes.

**Todo:**
- [ ] Write `tests/test_cli.py` first
- [ ] Write `t24/cli.py`
- [ ] Run full `pytest` suite
- [ ] Verify `out/dossier.json` matches DATA_CONTRACT schema

---

### ST-10 — Bob custom mode + skill
**Status:** [ ] pending

**Intent:** Add `.bob/modes/t24-mode.yaml` and `.bob/skills/t24-triage/SKILL.md`
so Bob can assist with triage natively.

**Expected outcomes:** Mode loads without errors; skill appears in skill list.

**Todo:**
- [ ] Write `.bob/modes/t24-mode.yaml`
- [ ] Write `.bob/skills/t24-triage/SKILL.md`

---

### ST-11 — docs/DATA_SOURCES.md
**Status:** [ ] pending

**Intent:** List every external source used in the project.

**Expected outcomes:** File exists; lists all four GHSA URLs and any other references.

**Todo:**
- [ ] Write `docs/DATA_SOURCES.md`

---

## 10. Out-of-Scope (for this 10-hour build)

- SBOM ingestion (only requirements.txt is supported)
- Multi-language support (Python AST only)
- CVSS scoring
- Automatic ENISA submission
- Dynamic / runtime analysis
- Anything under `dossier/` or `vercel.json`
