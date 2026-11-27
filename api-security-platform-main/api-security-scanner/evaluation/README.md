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

`eval-freeze-v1` (2026-11-27, commit 4cc01d5) is a **Layer 1 checkpoint**,
not the final freeze — the ML/DL layers have not been retrained yet, so
the final system does not exist. Freezing then would have spent the one
untouched target on a system that changes later.

The rule (2026-11-27): Juice Shop and crAPI stay held out and are each
scored **once**, at the end, on the final frozen system. If a result is
poor, report it as is. Any later fix becomes `v2` and is tested on a
different untouched app. When the final version is frozen, tag its commit
and record that hash in the results file, so the claim "this exact
version scored this" is checkable.

## The dataset

Development data comes from VAmPI, the DVWA replica and the toy app
only — never from a held-out target (the logger refuses Juice Shop and
crAPI outright). Collection: run the local pipeline with
`DATASET_LOG_DIR` set (plus `DATASET_TARGET_APP` and `DATASET_MODE`).
The log carries NO training label — the label would be circular if it
came from the scanner's own verdict. Instead each record carries the
join fields (target app, run id, mode, endpoint template, parameter,
probe type) and `evaluation/label_dataset.py` fills the label from the
ground-truth YAML (`label: 1` iff a ground-truth item matches the
record's template, parameter and probed category, respecting the item's
`modes`). The scanner's verdict is stored as the `scanner_label`
feature column, never as the label. Raw responses can contain secrets
(VAmPI returns plaintext passwords) — the logs are gitignored and must
never be committed.

First honest dataset (2026-11-27): 429 pairs, 30 positive / 399
negative — toy app 49 (5+), DVWA replica 60 (13+), VAmPI vulnerable
160 (11+), VAmPI secure 160 (1+; only the _debug exposure, which
persists by design).

## Ground-truth files

- `vampi-ground-truth.yaml` — VAmPI, 10 items (2026-11-27). VAmPI is a
  DEVELOPMENT target: every fix was tuned on it, so its scores are
  development numbers, not an evaluation. Items are mode-scoped
  (`modes`): GT-01–GT-04 apply in vulnerable mode only; GT-05–GT-10
  persist in secure mode too.
- `toy-ground-truth.yaml` — the toy ground-truth app, 3 planted vulns.
- `replica-ground-truth.yaml` — the DVWA-faithful replica, 5 planted
  vulns. `/flaky_slow/` is deliberately NOT listed: it is a negative
  control for time-based false positives (it sleeps on sleep keywords
  but is not a vulnerability).
- `juice-shop-ground-truth.yaml` — OWASP Juice Shop, 38 items (2026-11-27),
  written BEFORE any scan from the app's own challenge list
  (GET /api/Challenges, 118 challenges) plus the route handlers that prove
  each endpoint. In-scope rule: exercisable through the REST API without
  browser interaction AND a security bug a generic API scanner could in
  principle test. Recall is reported ONLY over the 38 in-scope items
  (56 of the 118 challenges); the 62 excluded challenges are listed in
  the file's `excluded:` section with the reason each is out of scope
  (client-side XSS, crypto puzzles, password-reset flows, CSRF, CAPTCHA,
  component advisories, easter eggs, policy files). Categories with no
  scanner check (NoSQL, JWT, SSTI, deserialization, file upload,
  misconfiguration, input validation, arbitrary file write, broken auth)
  are honest coverage gaps.
