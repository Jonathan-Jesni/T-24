---
name: cra-triage
description: >-
  Use when the user wants to run CRA triage on demo_product end-to-end: scan for
  vulnerabilities, fix AFFECTED findings with regression tests, and document
  UNDER_INVESTIGATION findings. Activates for phrases like "run cra-triage",
  "triage the product", "run the CRA workflow", or "start the incident workflow".
---

# CRA Triage Workflow

Follow every step in order. Use `update_todo_list` to track progress.

---

## Step 1 — Run the offline scan

Execute:
```
.venv\Scripts\python -m t24 scan demo_product --advisories advisories \
  --exploited CVE-2020-14343=2026-09-27T02:00:00Z --out out --offline
```

Read `out/dossier.json` using `execute_command` (the file is in `.bobignore`, use
`Get-Content out\dossier.json`). Parse the findings into three buckets:
- `affected`
- `under_investigation`
- `not_affected`

Surface the CRA clock deadlines from `dossier.clock` immediately.

---

## Step 2 — Save a baseline

Copy the dossier:
```
Copy-Item out\dossier.json out\baseline_dossier.json
```

This baseline is passed to `--baseline` later so the rescan can mark fixed findings
as `fixed` rather than `not_affected`.

---

## Step 3 — Handle each AFFECTED finding

For **each** finding with `status == "affected"`, use a subagent (or work inline for
a single finding) to perform the following sub-workflow:

### 3a. Create a fix branch

```
git checkout -b fix/<CVE>
```

where `<CVE>` is the CVE identifier in lowercase, e.g. `fix/CVE-2020-14343`.

### 3b. Write a failing regression test

Create `demo_product/tests/test_<cve_lower>.py` (e.g.
`demo_product/tests/test_cve_2020_14343.py`).

The test must:
1. Use the Flask test client (`app.test_client()`).
2. Exercise the exact vulnerable path described in `evidence` inside `dossier.json`.
3. **FAIL on current (unfixed) code** — the assertion must catch the exploit behaviour.
4. Be named `test_<cve_lower>_exploit_blocked`.

For CVE-2020-14343 (PyYAML arbitrary code execution via `yaml.full_load`), POST the
following payload to `/upload-config` and assert the response does NOT contain
`"EXPLOITED-42"`:

```
!!python/object/new:tuple [!!python/object/new:map [!!python/name:eval , ["'EXPLOITED-' + str(6*7)"]]]
```

Run the test to confirm it FAILS:
```
.venv\Scripts\python -m pytest demo_product/tests/test_cve_2020_14343.py -v
```

### 3c. Apply the fix

For CVE-2020-14343:
1. In `demo_product/config.py`: replace `yaml.full_load` with `yaml.safe_load`.
2. In `demo_product/app.py`: catch `yaml.YAMLError` in `upload_config` and return
   HTTP 400 with `{"error": "invalid config"}` on parse failure.
3. In `demo_product/requirements.txt`: update `PyYAML==5.3.1` to `PyYAML==6.0.2`.

General fix guidance for other CVEs: apply the minimum change that eliminates the
vulnerable symbol call identified in `evidence`. Do not refactor unrelated code.

### 3d. Run the test again — it must PASS

```
.venv\Scripts\python -m pytest demo_product/tests/test_cve_2020_14343.py -v
```

Confirm the test passes before continuing.

### 3e. Re-run the scan with --baseline

```
.venv\Scripts\python -m t24 scan demo_product --advisories advisories \
  --exploited CVE-2020-14343=2026-09-27T02:00:00Z \
  --out out --offline --baseline out/baseline_dossier.json
```

Read the new `out/dossier.json`. The patched finding must now show `status: "fixed"`.

### 3f. Commit the fix

```
git add demo_product/config.py demo_product/app.py demo_product/requirements.txt \
        demo_product/tests/test_cve_2020_14343.py
git commit -m "fix(cve-2020-14343): replace yaml.full_load with yaml.safe_load, add HTTP 400 guard"
```

Use the conventional commit format: `fix(<cve-lower>): <short description>`.

> **Important:** commit the fix ONLY on `fix/<CVE>`. Do NOT merge to main — main
> must keep the vulnerable version so the demo can be replayed.

---

## Step 4 — Handle each UNDER_INVESTIGATION finding

For **each** finding with `status == "under_investigation"`:

Create the file `out/questions_<cve>.md` (e.g. `out/questions_CVE-2023-32681.md`).

The file must contain:
1. The CVE identifier and package name.
2. The dossier `reason` field quoted verbatim.
3. A numbered list of specific facts a human must confirm before the verdict can
   change — derived from the reason, the evidence (if any), and the advisory text.
4. The advisory source URL from `advisory_source`.
5. The CRA deadline by which confirmation is needed (from `dossier.clock` if the
   finding is the exploited one, otherwise note that no clock is running).

Do NOT guess the final verdict. Leave the status as `under_investigation`.

---

## Step 5 — Summary

After completing all steps, print a triage summary table:

| CVE | Package | Status | Action taken |
|-----|---------|--------|--------------|
| CVE-2020-14343 | PyYAML | fixed | Branch fix/CVE-2020-14343, test + fix committed |
| CVE-2023-32681 | requests | under_investigation | out/questions_CVE-2023-32681.md created |
| CVE-2023-50447 | Pillow | not_affected | No action required |
| CVE-2024-22195 | jinja2 | not_affected | No action required |

State the CRA deadlines for any affected/exploited finding and confirm no
`out/` files are committed to main.
