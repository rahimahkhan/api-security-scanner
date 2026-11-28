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

`eval-freeze-v1` (2026-11-27, commit fa3da39b on GitHub — the local tag points at a local-only commit whose tree differs only in evaluation files; the scanner code is identical) is a **Layer 1 checkpoint**,
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

**This is a pilot / pipeline-validation set, not the real dataset.**
30 positives are ~10 unique bugs; rows are correlated (the same
endpoint probed many times) and there are only 3 independent groups
(VAmPI's two modes are one app — one group when splitting; training on
vulnerable mode and testing on secure mode is leakage). Leave-one-app-out
is unstable. Report confidence intervals and call every result on it
preliminary.

Each labeled pair also carries `probe_effective` (a response-based
rule, NOT the scanner's verdict: status changed, body diff > 0.1, an
error keyword appeared, the payload was reflected, or a time-based
probe whose injected delay fired). "The endpoint has this bug" is not
the same as "this probe's response shows it" — results are reported on
all positives and on effective-only positives. `scanner_label` is
excluded from every "ML alone" experiment (it is useful for ranking
Suspected findings, but a model using it just copies Layer 1).

### Shipped models, measured (2026-11-27, preliminary)

`evaluation/measure_models.py` — PR-AUC + recall at FPR 0.01/0.05/0.10
for the ML anomaly score, LSTM probability and autoencoder error,
against a simple rule baseline and the scanner's own verdict, plus the
ablation (signature only, +ML, +DL). Pooled (n=429, 30 positives,
base rate 0.07): **ML anomaly 0.225 [0.090, 0.364], LSTM 0.352 [0.199,
0.523], autoencoder 0.119 [0.052, 0.220] (near chance), signature
0.751 [0.608, 0.876], rule baseline 0.361, scanner verdict 0.629.
Ablation: signature + ML 0.730, shipped total 0.768 — the shipped total is statistically indistinguishable from signature alone (0.751 pooled; per group it is above signature on dvwa-replica, tied on toy-app, below on vampi — all well inside the CIs), so the ML/DL layers add no measurable benefit.** Effective-only
positives: signature 0.909, total 0.883. PR-AUC is scikit-learn's
`average_precision_score` — our implementation matches it to within
1e-16 on all eight score columns of this set — so tied scores form
one threshold step and the value does not depend on row order; an
earlier item-by-item version let the file order of tied items
inflate discrete scores (signature 0.797, rule 0.452, verdict 0.721)
and the bootstrap CI excluded the point estimate — fixed 2026-11-28. The models were trained on the
old data (not this pilot), so this measures generalization. The
signature number is optimistic — the signature layer was tuned on
these same development apps, so it is not a fair estimate for a new
app; the models' weak scores are the fairer comparison, but the sample
is still tiny. Full output: `~/workspace/dataset-logs/measurement-2026-11-28-fixed.txt` (the 2026-11-27 file is the pre-fix run).

**Consequence (2026-11-27, commit `707e164f`): ML/DL are experimental
advisory signals, weight 0 in the risk score.** Their points are
recorded (points_breakdown, ml_result, dl_result) but do not
contribute to `total_score`, and their agreement no longer discounts
the signature score. A Confirmed finding scores 40 + 30 proof bonus =
70 (CRITICAL) instead of 100. Until a model passes the ablation test,
no ML/DL claim stronger than "experimental advisory signal" belongs in
the README, the report, or the website.

### Retraining plan (2026-11-27)

Do NOT retrain on the 429 pairs — not credible. Retraining needs the
DynaST-Bench data (see below). When it exists: compare Logistic
Regression, Random Forest and a gradient-boosted model against the rule
baseline, using group-based splits; for text, test TF-IDF + Logistic
Regression against the LSTM. Success = beating the baseline, and
specifically ranking Suspected findings better, measured WITHIN the
Suspected group. If the autoencoder is still near chance, remove it and
say why.

### DynaST-Bench — training data (not the held-out test)

`j3ssie/dynast-bench` (MIT) — 19 apps, 559 planted vulns, 155
near-misses, 556 runnable PoCs, 634 endpoints; each app has a vuln/ +
safe/ twin and a machine-checkable answer key
(`VULNERABILITIES.yaml` + `SURFACE.yaml`). Prepared files:
`~/workspace/dynast-codespace/` (devcontainer + setup + README). Rules:
training data only (crAPI stays the final held-out test); ground truth
first, before scanning any app; one app at a time in `--solo` mode on a
2-core codespace (4-core only if an app fails for lack of resources);
stop the codespace when not in use; download the logs before deleting a
codespace (raw logs are gitignored by design, so they are lost with it).
Best first: graphql, fastapi, swagger, nextjs. Skip: network,
llmagent/llmchat, websocket, weirdproxy.

**Labeling rules for the DynaST data (2026-11-27):**
- Join by endpoint, parameter AND category. A SQLi probe on an
  endpoint that only has an SSTI bug is a negative for SQLi.
- Never label an unprobed category as negative. If the scanner has no
  check for a category, that vulnerability is out of scope, not a
  negative example.
- Group each vulnerable app with its patched twin as ONE group when
  splitting. Training on one and testing on the other is the same
  leakage as VAmPI's two modes.
- Write the mapping from DynaST's vulnerability types to the scanner's
  categories BEFORE scanning, and save it with a date.
- Note in the report that DynaST-Bench is new, from one author, and not
  peer-reviewed.

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
