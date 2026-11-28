# Evaluation methodology

The rules this project's numbers follow. `evaluation/README.md` documents
the mechanics (how to score a run, the dataset, the retraining plan);
this file states the methodology those mechanics implement, so an
examiner can judge whether a number means what it claims.

## 1. Scope — what the scanner is evaluated on

> The current scanner evaluates API security through **unauthenticated
> testing**. Vulnerabilities requiring an authenticated user context are
> excluded from the pre-authentication evaluation unless they can be
> independently and fairly tested without that context.

- **In scope** = the scanner has a matching check AND the bug is
  reachable without logging in (pre-auth), verified against the
  target's own answer key or documentation.
- Out of scope is not a negative. A bug the scanner cannot test is
  never counted as "not vulnerable" — see §3.

## 2. Ground truth

- Written **before** any scan, from the target's documentation, source
  or answer key — never from scan output. Each item records its
  template, parameter, category, how it was verified, and the date.
- An item added after a scan is flagged `added_after_scan` with the
  reason. That bias stays visible.
- **Never change ground truth to improve a number.** A genuine factual
  error in the ground truth (e.g. FA-06's parameter, corrected
  2026-11-27 from `'filename'` to `'name'` with the evidence in the
  item's `how_verified`) may be corrected, with the correction
  documented in the item. There is a regression test for FA-06
  (`tests/test_evaluation.py`).
- **Near-misses (hard negatives, 2026-11-28).** The bench documents
  safe code of the same shape as a scored bug. A near-miss qualifies
  as an explicit negative, listed under `near_misses:` in the
  ground-truth file, only when it is a **separately reachable
  endpoint** with a **matching scanner category**, verified in the
  app's source. Code-level look-alikes do **not** qualify: a dead
  helper function in the same file as the bug and a safe-twin-only fix
  are not separately observable endpoints, and the (template,
  parameter, category) join cannot express them. A finding on a
  near-miss **is** a false positive — the code is safe by the bench's
  design — so it counts in the headline FP and is also listed in the
  scorer's `near_miss_matches` bucket. The labeler labels pairs on
  one 0 with `matched_item` set and `near_miss: true`, so the dataset
  distinguishes a deliberate hard negative from a default negative.
  FastAPI 2026-11-28: 2 of 9 near-misses qualify (NM-SQL-001 →
  FA-NM-01 `/api/posts/list`; NM-TRAVERSAL-001 → FA-NM-02
  `/api/attachments/avatar-download`). NM-CACHE-001 is explicitly
  excluded: its endpoint `/api/cache/widget-scoped` carries a verified
  real XSS (FA-INC-03) — a near-miss for cache poisoning is not a
  negative for XSS. PHP 2026-11-28: 0 qualify — NM-LFI-001 and
  NM-SQL-001 are dead helpers in the same files as PH-01/PH-02, and
  NM-XSS-001 is the safe twin's fixed search.php, already covered by
  PH-06's `modes: [vulnerable]`.
- The DynaST-Bench mappings (which vulnerability types map to which
  scanner categories) are written before scanning, saved with a date,
  under `~/workspace/dynast-codespace/mapping-*.md`. DynaST-Bench is
  new, from one author, not peer-reviewed — the report says so.

## 3. Item status — one item, several dimensions

A ground-truth item carries a status in each dimension that applies.
The dimensions are **not mutually exclusive**: an endpoint can be
discovered and still require authentication for a particular test.

| Status | Meaning | How it is counted |
|---|---|---|
| `eligible` | The scanner can test this item under the declared (pre-auth) conditions. | In the recall and precision denominators. |
| `needs_auth` | Authentication is required; the scanner does not authenticate. Listed under `needs_auth:` in the ground-truth file. | Never TP, never FP, never a miss. Findings on it go in the scorer's `needs_auth_matches` bucket; labeler pairs on it are excluded entirely (never positive, never negative). |
| `not_discovered` | The relevant endpoint was not discovered. | A discovery miss, not a detection miss (§4). The scorer lists it under `missed_by_discovery` when `--surface`/`--discovered` are given. |
| `not_tested` | The test was not executed for another documented reason (e.g. a probe variant that does not exist yet). | Reported as a coverage gap, never a negative. |
| `detected` | The vulnerability was detected (Confirmed, or Confirmed + Suspected — reported separately). | A TP, counted once per unique bug (template, parameter, category). |
| `verified_negative` | The item was tested — the endpoint was discovered and the matching probes ran — and no finding resulted. | A true negative. Only `eligible` items on discovered endpoints can be verified negatives. |

The rule that governs all of it: **do not count a test as a true
negative merely because the scanner could not test it.** An
undiscovered endpoint, an unauthenticated route, and a tested-clean
endpoint are three different facts and are reported as three
different things.

A fourth bucket is reported separately and never improves a headline
number: **detected, wrong category** — the scanner found the bug but
filed it under another category. It stays a false negative for recall.

## 4. Metrics — discovery and detection measured separately

A failure at discovery must not be blamed on detection, and a perfect
detector on half the surface is still a weak scanner. All four are
reported per run, each with its denominator stated.

| Metric | Definition |
|---|---|
| Discovery recall | `R_discovery = endpoints discovered / eligible endpoints` (from the target's `SURFACE.yaml`; pre-auth subset reported separately). |
| Detection recall, conditional | `R_conditional = eligible bugs detected on discovered endpoints / eligible bugs on discovered endpoints`. Reported for Confirmed and for Confirmed + Suspected separately. |
| Overall vulnerability recall | `R_overall = eligible bugs detected / all eligible benchmark bugs` (= `R_discovery × R_conditional` in expectation, reported directly). |
| Precision | `TP / (TP + FP)` on unique bugs, **always with its n** (TP + FP). Never "100% precision" without the n. Reported for Confirmed and for Confirmed + Suspected separately. |

The scorer (`evaluation/score_scan.py`, `--surface` + `--discovered`)
produces all four, plus `missed_by_discovery` vs
`missed_despite_found` per item. Without those flags the report is the
detection-only view and says so.

**Suspected is evaluated on its own.** The Suspected tier has not
demonstrated discrimination between vulnerable and safe twins in the
reported comparisons (the same Suspected false alarms appear on both),
so Suspected numbers are never merged into the Confirmed headline.
The research question for the ML/DL models is whether they improve
Suspected ranking — measured *within* the Suspected group — not
whether they produce more findings.

## 5. Safe twins — the false-positive control

Each DynaST app ships a vulnerable app and a safe (patched) twin.
The twin is scored with `--mode safe`: items whose `modes` list does
not contain the mode do not apply, and when no items apply the report
states plainly that every finding is a false alarm by construction.

- A Confirmed finding on a safe twin is investigated with its request
  and response before any conclusion is drawn. If the reflection is
  real and the bench's answer key does not list it, the endpoint is
  recorded as an **incidental** ground-truth item with the date —
  excluded from both TP and FP in scoring, labeled 1 for training
  (the bug is real). If it is not real, it is an XSS-proof precision
  defect to fix.
- **Standing incidental rule (written 2026-11-28, before scanning
  php — applies to php with no exceptions):** every Confirmed finding
  that is not in the key gets checked by hand. If it is real, it is
  incidental. If not, it is a false positive. The decision depends on
  evidence, such as unescaped reflection in HTML, never on its effect
  on the score.
- **Ground-truth changes after scoring are reported both ways.**
  Reclassifying the 3 verified fastapi XSS findings moved Confirmed
  precision from 57% (n=7) to 100% (n=4). The report writes both
  numbers — "57% (n=7) before manual review, 100% (n=4) after
  reclassifying 3 verified real XSS findings" — never only the second
  one. n=4 is tiny: keep the confidence intervals, and call the number
  a development result.
- **Review runs in both directions.** Checking only the false
  positives pushes precision up. Misses get spot-checked too — for
  example whether a route in the key was mis-mapped — so errors in
  the scanner's disfavour get corrected as well. (First such check,
  2026-11-28: FA-02 CMDi — the sink is real in the vuln source and
  the probe was selected, but the labeled pair was not-effective; the
  dispatch detail is an open question for the session-3 log, not a
  mapping error.)
- Zero Confirmed findings on one safe twin is a promising result for
  those test conditions. It is not a claim of zero false positives
  across all safe APIs.
- **The safe twin is the main source of hard negatives.** The
  near-miss list is a small bonus. The main source is the matched
  pair: the same endpoint, probed with the same payload, behaves
  differently in the vulnerable and patched twins. Mode-scoped
  labeling captures it — a pair labels 1 in vuln mode and 0 in safe
  mode on the same template, parameter and category — and the report
  says so.

## 6. Dataset and retraining rules

- Labels come only from the join to ground truth (template, parameter,
  category), never from the scanner's own verdict. `scanner_label` is
  a feature column, excluded from every "ML alone" experiment.
- **Group = application.** A vulnerable app and its safe twin are ONE
  group when splitting; VAmPI's two modes are one group. Group-based
  (leave-one-app-out) cross-validation only.
- No retraining conclusions until the dataset is substantially
  expanded: target ~8 app groups / ~100 positives. Results are
  reported with bootstrap confidence intervals and called preliminary
  until then. The pilot (429 pairs, 30 positives, 3 groups) is
  pipeline validation, not training data.
- `probe_effective` separates "the endpoint has this bug" from "this
  probe's response shows it". Results are reported on all positives
  and on effective-only positives.

## 7. Held-out rule

Juice Shop and crAPI stay held out. Each is scored **once**, at the
end, on the final frozen system. A poor result is reported as is; any
later fix becomes `v2` and is tested on a different untouched app.
`eval-freeze-v1` (2026-11-27) is a Layer 1 checkpoint, not the final
freeze.

## 8. Scoring — what a number means

- A Confirmed finding scores **70** (40 signature points + 30 proof
  bonus). Suspected is capped below Confirmed; a pure ML/DL anomaly is
  Informational, not Suspected.
- ML/DL contribute **0** to the operational risk score
  (`ML_WEIGHT = DL_WEIGHT = 0.0`, 2026-11-27): they are experimental
  advisory signals, recorded but not scored. No ML/DL claim stronger
  than "experimental advisory signal" belongs in the README, the
  report, or the website until a model passes the ablation test.
- **Open work, not yet implemented:** 70 mixes severity and
  confidence in one field — a Confirmed low-impact issue and a
  Confirmed critical issue both score 70. The next scoring audit
  separates proof status (Confirmed / Suspected / Informational),
  severity (Low / Medium / High / Critical), confidence (strength of
  evidence), and the derived risk score into distinct fields.

## 9. Evaluation tiers (2026-11-28)

Fastapi's ground truth changed after its scan results were seen (the
3 incidental XSS items, 2026-11-28), so fastapi can no longer serve
as an untouched check. The apps are tiered so one honest check of the
pipeline survives before the final test.

- **Tier 1 — Development (VAmPI, fastapi):** scanner and rule changes
  are allowed here. Numbers from these apps are development results,
  not generalization — DVWA is the tuned target, VAmPI the tuned
  development target, fastapi the mapped-then-corrected one.
- **Tier 2 — Validation (php):** scanned with the scanner **frozen**,
  and its numbers reported, including any new incidental findings,
  using the written review rule (§5). The php runs (session 6 vuln
  rerun + session 7 safe) already ran on the current scanner code —
  one scanner-code commit since the runs (bf0af98c, 2026-11-28, "Log
  the fallback query param name in dataset records"), and it changes
  only the dataset log's parameter field — the value is passed only
  to log_dataset_pair, never to the probe, the detector or the score
  — so those runs ARE the frozen-scanner validation runs;
  what remains is re-scoring and re-labeling them with the current
  harness. No scanner change before php's numbers are reported.
  **Checkable evidence (2026-11-28):** the scanner code sessions 6
  and 7 ran is the code of commit `8c2e96b4`,
  2026-11-27, "Fix XSS findings stolen by SQL_Injection in evidence
  sweep" — the fix's presence in the runs is proven by the runs
  themselves (PH-06, reflected XSS, was missed in session 5 and
  recovered in session 6, which only happens with the fix in the
  run). That commit is the last scanner-code commit: nothing after
  it touches `main.py`, `detection/`, `core/` or `ml_pipeline/`.
  **php results were not used to change the scanner.** The harness
  changes since (incidental items, near-misses) came from looking at
  fastapi and are applied to php exactly as written — no
  php-specific adjustments. If php surfaces new real incidental
  findings, they are handled with the written review rule (§5), and
  the counts are reported before and after review, as with fastapi.
- **Tier 3 — Final held-out (crAPI, Juice Shop):** scored once, at
  the end, on the final frozen system (§7).
- **Training apps (nestjs, laravel, rails, springboot, gin, golang,
  jsp, aspnet):** scanned to build the training dataset. Collection
  stops at about 5–6 apps or ~60 unique positives (§11), so in
  practice this means fastapi, php, nestjs, plus one or two of
  laravel / rails / springboot — each checked with its own mapping
  first. They are development-tier in effect — scanner changes are
  allowed while the dataset is being built — but each app's mapping
  is written and dated BEFORE its scan, and its ground truth is
  fixed before scanning (except verified incidental findings per
  §5). No app is scanned before its mapping exists.

## 10. Two separate evaluations

These are easy to confuse, so they are named separately in the
report. They have different apps, different methods, and different
success rules.

1. **Scanner evaluation (signature layer).** Does the scanner prove
   what it claims, and does it find the endpoints? VAmPI and fastapi
   are development apps, php is the validation app, crAPI and Juice
   Shop are the final held-out apps (§9). Detection is scored by
   unique bugs (recall, precision with n); discovery by two-part
   recall.
2. **Model evaluation (ML/DL).** Do the ranking models add anything
   over the rule baseline? Leave-one-app-out cross-validation across
   the non-held-out apps (`evaluation/PROTOCOL-2026-11-28.md`), with
   the within-Suspected block as primary. **Any threshold is chosen
   inside the training folds only** — never on the fold being tested,
   never on pooled results. The held-out apps (crAPI, Juice Shop)
   are tested once, at the end, on the final frozen system. The
   current scripts use fixed FPR levels (0.01 / 0.05 / 0.10) rather
   than tuned thresholds, so no tuned threshold exists yet; the rule
   binds any future threshold tuning.

## 11. Data-collection stop rule (2026-11-28)

Collection can go on forever, so the limit is set now, before the
numbers arrive.

- Collect from **fastapi, php and nestjs**, plus **one or two more
  REST-style apps** with plenty of in-scope categories. Candidates
  are laravel, rails and springboot — each checked with its own
  mapping first, before any scan.
- Stop at about **5 to 6 apps**, or when there are enough unique
  bugs: a rough target of **60 or more unique (route, parameter,
  category) positives, with at least 5 in each of the main
  categories**.
- Set expectations now. With this much data, the **tabular models**
  (Logistic Regression, Random Forest, gradient boosting) are the
  realistic candidates. The LSTM and autoencoder will probably not
  clear the bar. Dropping them with the evidence is a valid outcome
  — it is a result, not a failure.
