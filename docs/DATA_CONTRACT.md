# T-24 Data Contract — `out/dossier.json`

Version: 1.0.0
Maintained by: this repository. The web UI (`dossier/`) consumes this file.
**Never change field names or types without updating both sides.**

---

## Canonical Example

```json
{
  "product": "demo_product",
  "scanned_at": "2026-09-27T02:00:00Z",
  "duration_s": 3.2,
  "summary": {
    "advisories": 4,
    "affected": 1,
    "not_affected": 2,
    "under_investigation": 1,
    "emergency_releases_avoided": 2
  },
  "clock": {
    "cve": "CVE-2020-14343",
    "aware_at": "2026-09-27T02:00:00Z",
    "early_warning_due": "2026-09-28T02:00:00Z",
    "notification_due": "2026-09-30T02:00:00Z",
    "final_report_due": "2026-10-11T02:00:00Z"
  },
  "findings": [
    {
      "cve": "CVE-2020-14343",
      "package": "PyYAML",
      "installed": "5.3.1",
      "affected_range": "<5.4",
      "fixed_version": "5.4",
      "symbols": ["full_load"],
      "status": "affected",
      "justification": null,
      "evidence": [
        {
          "file": "demo_product/app.py",
          "line": 18,
          "function": "upload_config",
          "call": "yaml.full_load"
        }
      ],
      "reason": "full_load is reachable from route /upload-config",
      "advisory_source": "https://github.com/advisories/GHSA-8q59-q68h-6hv4",
      "drafts": [
        "out/drafts/early_warning_CVE-2020-14343.md",
        "out/drafts/notification_CVE-2020-14343.md"
      ]
    }
  ],
  "coverage": {
    "files_found": 3,
    "files_parsed": 3
  },
  "vex_path": "out/vex.json"
}
```

---

## Field Reference

### Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `product` | string | yes | Name or path of the scanned product directory |
| `scanned_at` | string (ISO 8601 UTC) | yes | Timestamp when the scan started |
| `duration_s` | number | yes | Wall-clock seconds the scan took |
| `summary` | object | yes | Aggregate counts — see below |
| `clock` | object \| null | yes | CRA deadline block — `null` when no finding is both `affected` AND actively exploited |
| `findings` | array | yes | One entry per advisory scanned; never empty |
| `coverage` | object | yes | File parse coverage across the whole product |
| `vex_path` | string | yes | Relative path to `out/vex.json` |

---

### `summary` object

| Field | Type | Description |
|-------|------|-------------|
| `advisories` | integer | Total number of advisories processed |
| `affected` | integer | Count of findings with `status == "affected"` |
| `not_affected` | integer | Count of findings with `status == "not_affected"` |
| `under_investigation` | integer | Count of findings with `status == "under_investigation"` |
| `emergency_releases_avoided` | integer | Count of `not_affected` findings (same as `not_affected`); surfaced separately for the UI headline metric |

---

### `clock` object (or null)

`clock` is **non-null only** when at least one finding has `status == "affected"` AND the
user supplied `--actively-exploited <CVE>=<ISO8601>` on the CLI.
When `clock` is non-null it contains data for exactly one CVE (the first affected+exploited one).

| Field | Type | Description |
|-------|------|-------------|
| `cve` | string | The CVE identifier |
| `aware_at` | string (ISO 8601 UTC) | Moment the manufacturer became aware — supplied by user |
| `early_warning_due` | string (ISO 8601 UTC) | `aware_at + 24 hours` — CRA Art. 14 §1 deadline |
| `notification_due` | string (ISO 8601 UTC) | `aware_at + 72 hours` — CRA Art. 14 §2 deadline |
| `final_report_due` | string (ISO 8601 UTC) | `aware_at + 14 days` — CRA Art. 14 §3 deadline |

---

### `findings` array — each element

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `cve` | string | no | CVE identifier (e.g. `"CVE-2020-14343"`) |
| `package` | string | no | PyPI package name as declared in requirements.txt |
| `installed` | string | no | Installed version string |
| `affected_range` | string | no | PEP 440 specifier string from advisory (e.g. `"<5.4"`) |
| `fixed_version` | string | no | First fixed version from advisory |
| `symbols` | array of strings | no | Vulnerable symbol names extracted from advisory (verbatim-checked); `[]` when none named |
| `status` | string (enum) | no | One of: `affected` \| `not_affected` \| `under_investigation` \| `fixed` |
| `justification` | string \| null | yes | OpenVEX justification string when `status == "not_affected"`, else `null`. Valid values: `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`, `component_not_present` |
| `evidence` | array of hop objects | no | Ordered call-graph path from entry point to vulnerable symbol; `[]` when not reachable or not applicable |
| `reason` | string | no | Human-readable one-liner explaining the verdict |
| `advisory_source` | string (URL) | no | Source URL parsed from the `SOURCE:` line in the advisory markdown |
| `drafts` | array of strings | no | Relative paths to generated ENISA draft files; `[]` when no report is due |

---

### Evidence hop object (element of `findings[].evidence`)

| Field | Type | Description |
|-------|------|-------------|
| `file` | string | Relative path to the source file (relative to repo root) |
| `line` | integer | 1-based line number of the call |
| `function` | string | Name of the enclosing function or `"<module>"` for module-level code |
| `call` | string | The call expression as it appears in source (e.g. `"yaml.full_load"`) |

---

### `coverage` object

| Field | Type | Description |
|-------|------|-------------|
| `files_found` | integer | Total `.py` files discovered under the product directory |
| `files_parsed` | integer | Files successfully parsed by `ast.parse` without error |

`not_affected` with `justification == "vulnerable_code_not_in_execute_path"` is only
emitted when `files_parsed == files_found`. Any parse failure forces `under_investigation`
for all in-range findings with symbols.

---

## Invariants (enforced by `t24/verdict.py`)

1. `status` is always set by deterministic logic — never by the LLM.
2. `justification` is `null` for every status other than `not_affected`.
3. `evidence` is `[]` when `status != "affected"`.
4. `drafts` is `[]` when `clock` is `null` or `status != "affected"`.
5. `symbols` contains only strings that appear verbatim in the advisory text.
6. `clock` is `null` unless the user explicitly passed `--actively-exploited`.

---

## Versioning

This contract is at **v1.0.0**. Breaking changes require:
1. A version bump in this file.
2. A migration note in `docs/PLAN.md`.
3. Coordinated update with the `dossier/` team.
