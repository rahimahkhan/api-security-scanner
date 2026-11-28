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
