# Evaluation

How the scanner's numbers are produced, so an examiner can reproduce them
from this repo alone.

## Scoring a run

1. Write the ground truth FIRST, from the target's documentation and source
   (never from scan output). Each item records its template, parameter,
   category, how it was verified, and the date it was established. An item
   added after a scan is flagged `added_after_scan` with the reason — that
   bias must be visible, not hidden.
2. Run the scanner and save its findings as a `.txt` file (one finding per
   line: `[status] severity attack_type :: url (score=X)`).
3. Score it:

```bash
python3 evaluation/score_scan.py \
  --ground-truth evaluation/vampi-ground-truth.yaml \
  --findings <path/to/findings.txt> \
  --run-name <target>-<mode>-<date> \
  --out-dir <results dir>
```

## What the numbers mean

- Findings are normalized to endpoint templates (`/users/v1/{username}`)
  and scored by (template, parameter, category). Four Confirmed SQLi rows
  on the same sink are ONE bug, not four.
- **Confirmed** and **Confirmed + Suspected** are reported separately,
  each with recall and precision on unique bugs. Precision is always
  reported with its n (TP + FP) — three confirmations is a tiny sample.
- **Detected, wrong category**: the scanner found the bug but filed it
  under another category (a ground-truth item lists the categories that
  count via `also_detected_by`). These stay FN for recall and are
  reported separately; they never improve the headline numbers.

## Freezing a version for evaluation

When a version is frozen for a held-out run, tag the commit
(e.g. `eval-freeze-v1`) and record that hash in the results file, so the
claim "this exact version scored this" is checkable.

## Ground-truth files

- `vampi-ground-truth.yaml` — VAmPI, 10 items (2026-11-27). VAmPI is a
  DEVELOPMENT target: every fix was tuned on it, so its scores are
  development numbers, not an evaluation. The held-out target gets its
  own file here, written before the scan.
- `juice-shop-ground-truth.yaml` — OWASP Juice Shop, 38 items (2026-11-27),
  written BEFORE any scan from the app's own challenge list
  (GET /api/Challenges, 118 challenges) plus the route handlers that prove
  each endpoint. In-scope rule: exercisable through the REST API without
  browser interaction AND a security bug a generic API scanner could in
  principle test. Categories with no scanner check (NoSQL, JWT, SSTI,
  deserialization, file upload, misconfiguration, input validation,
  arbitrary file write, broken auth) are honest coverage gaps.
  The frozen scanner for this run is tagged `eval-freeze-v1` (commit
  4cc01d5); record that hash in the results file.
