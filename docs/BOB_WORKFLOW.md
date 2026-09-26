# T-24 Bob Integration — Workflow Reference

T-24 uses five Bob-native features to turn a static analysis engine into a
live incident-response tool.

---

## Features and Where They Are Used

### 1. Custom Mode — CRA Incident Commander (`.bob/custom_modes.yaml`)

Slug `cra-incident-commander`. Restricts file-edit access to `demo_product/`
and `out/` via `fileRegex`, blocks edits to `t24/` during live triage, and
embeds seven operating rules (run scan first, never state a verdict not in
the dossier, cite every claim) directly in the system prompt. Appears in the
Bob mode picker on save.

### 2. Skill — cra-triage (`.bob/skills/cra-triage/SKILL.md`)

Activated by `/cra-triage` or auto-matched from phrases like "run CRA triage".
Encodes the five-step incident workflow: run the offline scan → save a
baseline → fix each AFFECTED finding with a failing regression test → document
each UNDER_INVESTIGATION finding → print a summary. Exact CLI commands, file
paths, and test payloads are embedded so Bob never guesses.

### 3. Rules via AGENTS.md

Read by every Bob agent before any action. Enforces the `dossier/` ownership
boundary, the deterministic-verdict rule (LLM never sets status), the
verbatim-symbol check, and the no-network-in-tests constraint. Acts as hard
guardrails that override any mode or skill instruction.

### 4. Plan Mode and Agent Mode

**Plan mode** reads `out/dossier.json`, maps CVEs to fix branches, and drafts
`out/questions_<cve>.md` for uncertain findings without edits. **Agent mode**
(via the CRA Incident Commander) writes tests, edits `demo_product/`, runs
pytest, re-runs the scan with `--baseline`, and commits fixes.

### 5. Subagents

The skill spawns a subagent per AFFECTED finding so the parent context (scan
results, baseline dossier) stays intact while each fix branch and commit are
isolated.

### 6. Rollback and Commit Generation

Each fix lands on `fix/<CVE>` — main is never touched. Bob generates
conventional commits (`fix(cve-2020-14343): ...`) as specified in the skill.
The mode's `fileRegex` prevents accidental edits outside `demo_product/` and
`out/`.

---

## Data Flow

```
advisories/ + demo_product/
        |
        v
python -m t24 scan (offline, uses cache/ fixtures)
        |
        v
out/dossier.json  ──► out/baseline_dossier.json
        |
        ├─ AFFECTED  ──► fix/<CVE> branch ──► test (fail) ──► fix ──► test (pass)
        │                ──► rescan --baseline ──► status: "fixed"
        │
        └─ UNDER_INVESTIGATION ──► out/questions_<cve>.md (human review)
```
