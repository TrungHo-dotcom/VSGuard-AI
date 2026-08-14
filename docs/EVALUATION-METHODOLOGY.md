# Evaluation Methodology — Held-Out Validation Policy

**Status:** in effect from 2026-08-11. Applies to all detection-rule and
threshold changes to VEXGuard from this date forward.

## The problem this document fixes

The headline numbers in `docs/03-TEST-RESULTS.md` and
`vexguard-results/METRICS.md` (100.0% STRICT precision on DataDog, 0 false
positives, etc.) were produced by a process that iteratively tuned
detection rules and score thresholds against the same DataDog and VsMex
corpora now used to *report* those numbers. `docs/CHANGES-v3.md` documents
this explicitly — for example, the two-tier PRIMARY/SUPPORTING static
scoring split exists specifically because the flat-sum v2 model scored
`TabNine.tabnine-vscode` (a real, benign extension in the DataDog control
set) at 235 points and wrongly called it MALICIOUS; the fix was validated
by re-running against that same sample.

This is standard, reasonable iteration for building a rule-based detector.
It is also, by construction, **not** a measurement of how the engine
performs on samples it has never influenced. A rule tuned to stop flagging
one specific benign extension is guaranteed to score well on that
extension afterward — that isn't evidence it will score well on the next
unseen one. Reported precision/recall to date should be read as **tuning-set
performance**, not a validated generalization estimate.

This document does not — cannot — retroactively fix that. What it does is
draw a line: from here on, a frozen partition of each corpus is off-limits
for tuning, and only results measured on that partition may be cited as
evidence that a change generalizes.

## The held-out partition

`analysis/holdout_split.py` drew a stratified 25% sample (by
`dataset × tier × label`, fixed seed `20260811`) from every corpus and
recorded it in `analysis/holdout_ids.json` (991 of 3,962 total samples).
Stratification means the holdout preserves the same tier/label composition
as the full corpus in each group — see the console output of that script
for the per-group counts.

`analysis/holdout_ids.json` is committed as-is and **must not be
regenerated** except by deliberately deleting it first (the script refuses
to overwrite an existing file, on purpose). Redrawing it silently would
let a sample that was already used for tuning re-enter the "unseen" pool.

## Policy going forward

1. **Never inspect or tune against a holdout sample.** If you're adding a
   rule in response to a specific false negative/positive, first check
   whether that sample is in `holdout_ids.json`. If it is, either accept
   the miss for now or find a different, non-holdout sample exhibiting the
   same technique to develop the rule against.
2. **Every rule/threshold change must be validated in two passes:**
   - Run `node benchmark.js --datasets all --concurrency 8` as usual (or
     `--limit` for a quick check) to see the effect on the tuning
     population — this is fine for iteration, exactly as before.
   - Before merging, re-run metrics computed **only** on the samples listed
     in `analysis/holdout_ids.json` (join on `dataset` + `id` + `version`
     against the produced `results-*.csv`/`.jsonl`). A short filter script
     is sufficient; it does not need to be part of `benchmark.js` itself.
3. **Only holdout-partition numbers may be cited as evidence a change
   generalizes** (in commit messages, `CHANGES-v*.md`, or any future
   results writeup). Tuning-set numbers remain useful for iteration but
   should be labeled as such, not presented as the headline result.
4. **If holdout performance and tuning-set performance diverge
   significantly** for a given rule, that is itself the finding — it means
   the rule is closer to memorizing the tuning corpus than describing the
   underlying technique, and is a signal to generalize the rule rather
   than to ship it.

## Known limitation of this policy

The holdout was drawn *after* all tuning that produced the current
STRICT/TRIAGE thresholds and rule set — so even holdout-partition numbers
measured today still reflect a detector shaped by having seen the rest of
the corpus (including, indirectly, whatever the holdout samples have in
common with it). The clean guarantee only starts applying to *future*
changes measured against this exact frozen partition. Today's numbers,
holdout-restricted or not, are not a substitute for evaluating VEXGuard
against a corpus assembled after 2026-08-11.
