# AGENTS.md — Rules for All AI Agents Working on T-24

This file is read by every AI agent (Bob, GitHub Copilot, etc.) before touching
this repository. Follow every rule unconditionally.

---

## 1. Ownership Boundaries

| Directory / File | Owner | Rule |
|------------------|-------|------|
| `t24/` | This engineer | Read + write |
| `tests/` | This engineer | Read + write |
| `demo_product/` | This engineer | Read + write |
| `advisories/` | This engineer | Read + write |
| `cache/` | This engineer | Read + write |
| `.bob/` | This engineer | Read + write |
| `docs/` | This engineer | Read + write |
| `out/` | Generated | Read + write (never commit) |
| `dossier/` | **Teammate — DO NOT TOUCH** | **Never create, edit, or delete any file here** |
| `vercel.json` | **Teammate — DO NOT TOUCH** | **Never edit** |

**Violation of the `dossier/` boundary is the most critical rule in this file.**

---

## 2. The Verdict Is Deterministic — The LLM Never Sets It

- The LLM is permitted **only** to extract advisory fields: package name,
  affected version range, fixed version, symbol names, preconditions.
- The LLM **must never** suggest, compute, or output a VEX status (`affected`,
  `not_affected`, `under_investigation`, `fixed`).
- The verdict is set exclusively by `t24/verdict.py` following the decision tree
  in `docs/PLAN.md § 4.4`.
- If you are writing code that assigns `status` anywhere other than `t24/verdict.py`,
  stop and reconsider.

---

## 3. `not_affected` Requires Complete Parse Coverage

- The justification `vulnerable_code_not_in_execute_path` **must not** be emitted
  unless `coverage.files_parsed == coverage.files_found`.
- If any `.py` file under the product directory fails `ast.parse`, all in-range
  findings with named symbols must be `under_investigation`.
- Never round up or assume a file is clean without parsing it.

---

## 4. Every Claim in a Draft Report Must Cite a Source

- Evidence file paths must be relative to the repository root and include a line
  number (`file:line`).
- Advisory claims must cite the advisory source URL or a specific line/section of
  the advisory markdown.
- Do not write sentences like "the vulnerability affects X" without immediately
  following them with a citation.

---

## 5. Verbatim Symbol Check

- Every symbol name extracted by the LLM is dropped unless it appears
  **character-for-character** (case-sensitive) as a substring of the raw
  advisory text.
- This check is performed in `t24/advisory.py` after every LLM call.
- Do not relax or skip this check. Do not add fuzzy matching.

---

## 6. Tests Before Implementation

- For every new module, write the test file first, then the implementation.
- Tests must pass before any dependent module is written.
- No test may make a network call. Use `cache/` fixtures or `unittest.mock`.
- The test suite must remain green at every commit.

---

## 7. Module Size Limit

- No file under `t24/` may exceed **300 lines** (excluding blank lines and comments).
- If a module approaches the limit, split responsibilities into a helper module.
- `tests/` files are exempt from the 300-line limit.

---

## 8. `out/dossier.json` Must Match `docs/DATA_CONTRACT.md` Exactly

- Field names, types, and nesting must match the contract specification.
- The `status` enum is: `affected | not_affected | under_investigation | fixed`.
- `justification` is `null` for every status except `not_affected`.
- `evidence` is `[]` for every status except `affected`.
- `clock` is `null` unless `--actively-exploited` was passed on the CLI.
- If you add, rename, or remove a field, update `docs/DATA_CONTRACT.md` first
  and notify the `dossier/` team.

---

## 9. No Network Calls in Tests

- All LLM calls in tests must be mocked via `unittest.mock.patch` or pre-populated
  `cache/` JSON fixtures.
- All HTTP calls (watsonx.ai, Fireworks) must be mockable via environment-variable
  injection or dependency injection — never hardcoded.
- The full test suite must run without internet access.

---

## 10. Advisory Source Files

- Each advisory in `advisories/` must have a `SOURCE:` line with the full
  GitHub Advisory Database URL.
- Advisory text must be accurate to the GHSA record (CC-BY-4.0 licence).
- Do not fabricate advisory text. If you are uncertain, leave a `TODO:` comment.
- **Advisory facts must come from a fetched GHSA record, never from memory.**
  Fetch with `curl -s https://api.github.com/advisories/<GHSA_ID>` and build
  `advisories/<CVE>.md` from the returned `summary`, `description`,
  `vulnerable_version_range`, and `first_patched_version` fields.
  Include a `SOURCE: https://github.com/advisories/<GHSA_ID>` line and a
  `Fetched: <date>` line in every advisory file.
  Save the raw API response as `advisories/<GHSA_ID>.json`.
- **Advisory files contain only published text.** Do not add `## Vulnerable Symbols`,
  `## Preconditions`, or any other annotation section — those are editorial
  interpretations, not GHSA-published text. The engine must extract symbols from
  published description text; pre-annotating them makes the verbatim check
  self-fulfilling.
- **Expected answers live in `tests/fixtures/` only.** The file
  `tests/fixtures/expected_extractions.json` holds our expected LLM extraction
  results for test assertions. It is never read by the engine at runtime.

---

## 11. Commit Hygiene

- Never commit files under `out/` (generated outputs).
- Never commit secrets (`WATSONX_APIKEY`, `FIREWORKS_API_KEY`).
- `cache/` fixtures may be committed to enable offline demo.
- `out/` and any `*.env` files must be in `.bobignore` / `.gitignore`.

---

## 12. OpenVEX Compliance

- `out/vex.json` must conform to OpenVEX 0.2.0.
- Required top-level keys: `@context`, `@id`, `timestamp`, `author`, `tooling`,
  `statements`.
- Each statement must include `vulnerability.name`, `products`, `status`.
- `justification` is included only when `status == "not_affected"`.

---

## Quick Reference — Module Responsibilities

| Module | Does | Does not |
|--------|------|----------|
| `advisory.py` | LLM extraction, verbatim check, cache | Set verdict |
| `inventory.py` | Version-range check | Parse source code |
| `reach.py` | AST call graph, evidence paths | Call LLM |
| `verdict.py` | Set OpenVEX status | Call LLM, parse files |
| `clock.py` | CRA deadline arithmetic | Set verdict |
| `vex.py` | Serialize OpenVEX JSON | Set verdict |
| `report.py` | Render ENISA Markdown drafts | Call LLM, set verdict |
| `cli.py` | Orchestrate all modules, write outputs | Implement business logic |
