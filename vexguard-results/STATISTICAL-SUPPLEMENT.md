# VEXGuard — Statistical Supplement

> **Supplementary analysis — not part of the graded engine.**
> Computed on top of the existing `vexguard-results/results-*.jsonl` files.
> Does not re-run the engine and does not alter any verdict.
> Generated: 2026-08-13T14:50:43.033085+00:00

This supplement adds confidence intervals, threshold-independent discriminative power, an ablation of the static/dynamic/corroboration contributions, and per-technique recall to the point estimates already reported in `METRICS.md`. See `docs/EVALUATION-METHODOLOGY.md` for the held-out validation policy this supplement does **not** substitute for: every number below is still measured on the corpus used to tune the detection rules.

## DataDog corpus  (n = 238)

### STRICT

- TP=55 FP=11 FN=83 TN=89
- Precision: 83.3% (95% CI 72.6%–90.4%, n=66)
- Recall: 39.9% (95% CI 32.1%–48.2%, n=138)
- Specificity (TNR): 89.0% (95% CI 81.4%–93.7%, n=100)
- F1 (bootstrap, 2000 resamples): 0.539 (95% CI 0.456–0.621)
- MCC (bootstrap): 0.318 (95% CI 0.210–0.426)
- Balanced accuracy (bootstrap): 0.645 (95% CI 0.594–0.696)

### TRIAGE

- TP=68 FP=39 FN=70 TN=61
- Precision: 63.6% (95% CI 54.1%–72.1%, n=107)
- Recall: 49.3% (95% CI 41.1%–57.5%, n=138)
- Specificity (TNR): 61.0% (95% CI 51.2%–70.0%, n=100)
- F1 (bootstrap, 2000 resamples): 0.555 (95% CI 0.475–0.625)
- MCC (bootstrap): 0.101 (95% CI -0.027–0.222)
- Balanced accuracy (bootstrap): 0.551 (95% CI 0.486–0.611)

**ROC-AUC (raw score vs. label): 0.613 · PR-AUC: 0.721**  — threshold-independent view; note the cross-modality corroboration rule can escalate a verdict to MALICIOUS without raising `score`, so a handful of points are not explained by score alone.

**Ablation (STRICT confusion matrix per modality):**

| Modality | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| static_only | 47 | 11 | 91 | 89 | 81.0% | 34.1% |
| dynamic_only | 39 | 0 | 99 | 100 | 100.0% | 28.3% |
| combined | 55 | 11 | 83 | 89 | 83.3% | 39.9% |

Of 55 STRICT true positives, 0 (0.0%) were escalated by the cross-modality corroboration rule specifically — i.e. would not have reached MALICIOUS on either modality's score alone.

**Recall by technique family (`intel.families`, ground-truth positives only):**

| Family | n | Caught | Recall |
|---|---:|---:|---:|
| (uncategorised) | 91 | 14 | 15.4% |
| downloader | 18 | 18 | 100.0% |
| c2 | 10 | 9 | 90.0% |
| stealer | 6 | 3 | 50.0% |
| reverse_shell | 6 | 6 | 100.0% |
| obfuscated | 4 | 2 | 50.0% |
| dropper | 3 | 3 | 100.0% |

## VsMex code-level subset (primary)  (n = 100)

### STRICT

- TP=0 FP=11 FN=0 TN=89
- Precision: 0.0% (95% CI 0.0%–25.9%, n=11)
- Recall: —
- Specificity (TNR): 89.0% (95% CI 81.4%–93.7%, n=100)
- F1 (bootstrap, 2000 resamples): 0.000 (95% CI 0.000–0.000)
- MCC (bootstrap): 0.000 (95% CI 0.000–0.000)
- Balanced accuracy (bootstrap): 0.445 (95% CI 0.415–0.475)

### TRIAGE

- TP=0 FP=39 FN=0 TN=61
- Precision: 0.0% (95% CI 0.0%–9.0%, n=39)
- Recall: —
- Specificity (TNR): 61.0% (95% CI 51.2%–70.0%, n=100)
- F1 (bootstrap, 2000 resamples): 0.000 (95% CI 0.000–0.000)
- MCC (bootstrap): 0.000 (95% CI 0.000–0.000)
- Balanced accuracy (bootstrap): 0.304 (95% CI 0.255–0.350)

ROC/PR-AUC: not computable (single class in this section).

**Ablation (STRICT confusion matrix per modality):**

| Modality | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| static_only | 0 | 11 | 0 | 89 | 0.0% | — |
| dynamic_only | 0 | 0 | 0 | 100 | — | — |
| combined | 0 | 11 | 0 | 89 | 0.0% | — |

Of 0 STRICT true positives, 0 (—) were escalated by the cross-modality corroboration rule specifically — i.e. would not have reached MALICIOUS on either modality's score alone.

## VsMex full corpus (pessimistic bound)  (n = 100)

### STRICT

- TP=0 FP=11 FN=0 TN=89
- Precision: 0.0% (95% CI 0.0%–25.9%, n=11)
- Recall: —
- Specificity (TNR): 89.0% (95% CI 81.4%–93.7%, n=100)
- F1 (bootstrap, 2000 resamples): 0.000 (95% CI 0.000–0.000)
- MCC (bootstrap): 0.000 (95% CI 0.000–0.000)
- Balanced accuracy (bootstrap): 0.445 (95% CI 0.415–0.475)

### TRIAGE

- TP=0 FP=39 FN=0 TN=61
- Precision: 0.0% (95% CI 0.0%–9.0%, n=39)
- Recall: —
- Specificity (TNR): 61.0% (95% CI 51.2%–70.0%, n=100)
- F1 (bootstrap, 2000 resamples): 0.000 (95% CI 0.000–0.000)
- MCC (bootstrap): 0.000 (95% CI 0.000–0.000)
- Balanced accuracy (bootstrap): 0.304 (95% CI 0.255–0.350)

ROC/PR-AUC: not computable (single class in this section).

**Ablation (STRICT confusion matrix per modality):**

| Modality | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| static_only | 0 | 11 | 0 | 89 | 0.0% | — |
| dynamic_only | 0 | 0 | 0 | 100 | — | — |
| combined | 0 | 11 | 0 | 89 | 0.0% | — |

Of 0 STRICT true positives, 0 (—) were escalated by the cross-modality corroboration rule specifically — i.e. would not have reached MALICIOUS on either modality's score alone.

## Combined (all corpora pooled)  (n = 238)

### STRICT

- TP=55 FP=11 FN=83 TN=89
- Precision: 83.3% (95% CI 72.6%–90.4%, n=66)
- Recall: 39.9% (95% CI 32.1%–48.2%, n=138)
- Specificity (TNR): 89.0% (95% CI 81.4%–93.7%, n=100)
- F1 (bootstrap, 2000 resamples): 0.539 (95% CI 0.456–0.621)
- MCC (bootstrap): 0.318 (95% CI 0.210–0.426)
- Balanced accuracy (bootstrap): 0.645 (95% CI 0.594–0.696)

### TRIAGE

- TP=68 FP=39 FN=70 TN=61
- Precision: 63.6% (95% CI 54.1%–72.1%, n=107)
- Recall: 49.3% (95% CI 41.1%–57.5%, n=138)
- Specificity (TNR): 61.0% (95% CI 51.2%–70.0%, n=100)
- F1 (bootstrap, 2000 resamples): 0.555 (95% CI 0.475–0.625)
- MCC (bootstrap): 0.101 (95% CI -0.027–0.222)
- Balanced accuracy (bootstrap): 0.551 (95% CI 0.486–0.611)

**ROC-AUC (raw score vs. label): 0.613 · PR-AUC: 0.721**  — threshold-independent view; note the cross-modality corroboration rule can escalate a verdict to MALICIOUS without raising `score`, so a handful of points are not explained by score alone.

**Ablation (STRICT confusion matrix per modality):**

| Modality | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| static_only | 47 | 11 | 91 | 89 | 81.0% | 34.1% |
| dynamic_only | 39 | 0 | 99 | 100 | 100.0% | 28.3% |
| combined | 55 | 11 | 83 | 89 | 83.3% | 39.9% |

Of 55 STRICT true positives, 0 (0.0%) were escalated by the cross-modality corroboration rule specifically — i.e. would not have reached MALICIOUS on either modality's score alone.

**Recall by technique family (`intel.families`, ground-truth positives only):**

| Family | n | Caught | Recall |
|---|---:|---:|---:|
| (uncategorised) | 91 | 14 | 15.4% |
| downloader | 18 | 18 | 100.0% |
| c2 | 10 | 9 | 90.0% |
| stealer | 6 | 3 | 50.0% |
| reverse_shell | 6 | 6 | 100.0% |
| obfuscated | 4 | 2 | 50.0% |
| dropper | 3 | 3 | 100.0% |

## Operational metrics

- Samples with timing data: 238
- Median analysis duration: 24066 ms
- p95 analysis duration: 107925 ms
- Max analysis duration: 193060 ms
- Timeout rate: 0.8%
