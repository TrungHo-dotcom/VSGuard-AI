# VEXGuard — Evaluation Report

Generated: 2026-08-06T15:06:28.595Z
Engine: static 3.0.0 · sandbox 3.0.0 · orchestrator 3.0.0

## Decision rules

| Rule | Positive class | Use |
|------|----------------|-----|
| **STRICT** | verdict = MALICIOUS | auto-block / removal decisions |
| **TRIAGE** | verdict = MALICIOUS or SUSPICIOUS | analyst review queue |

## DataDog corpus (Dataset_Malicious + Dataset_Benign)

> Balanced ground truth from the corpus itself: every sample under the malicious tree is a confirmed malicious package, every sample under the benign tree is a top-installed marketplace extension. This is the primary precision/recall measurement.

Samples: **172**  ·  malicious-labelled: 123  ·  benign-labelled: 49

### STRICT (positive = MALICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 54 | FN = 69 |
| **Actual BENIGN**    | FP = 0 | TN = 49 |

Precision **100.0%** · Recall **43.9%** · F1 **61.0%** · Accuracy **59.9%** · MCC **0.427** · n = 172

### TRIAGE (positive = MALICIOUS or SUSPICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 63 | FN = 60 |
| **Actual BENIGN**    | FP = 7 | TN = 42 |

Precision **90.0%** · Recall **51.2%** · F1 **65.3%** · Accuracy **61.0%** · MCC **0.339** · n = 172

### Verdict distribution by evidence tier

| Tier | n | MALICIOUS | SUSPICIOUS+ | BENIGN | ERROR | strict detection rate |
|------|---|-----------|-------------|--------|-------|----------------------|
| code | 123 | 54 | 63 | 60 | 0 | 43.9% |
| benign | 49 | 0 | 7 | 42 | 0 | 0.0% |

## VsMex — CODE-LEVEL subset (primary)

> Only extensions Microsoft removed as Malware / Malicious / Potentially malicious, plus the benign controls so precision is defined. This is the population a static+behavioural engine is built to detect.

Samples: **1300**  ·  malicious-labelled: 1251  ·  benign-labelled: 49

### STRICT (positive = MALICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 379 | FN = 872 |
| **Actual BENIGN**    | FP = 0 | TN = 49 |

Precision **100.0%** · Recall **30.3%** · F1 **46.5%** · Accuracy **32.9%** · MCC **0.127** · n = 1300

### TRIAGE (positive = MALICIOUS or SUSPICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 679 | FN = 572 |
| **Actual BENIGN**    | FP = 7 | TN = 42 |

Precision **99.0%** · Recall **54.3%** · F1 **70.1%** · Accuracy **55.5%** · MCC **0.153** · n = 1300

### Verdict distribution by evidence tier

| Tier | n | MALICIOUS | SUSPICIOUS+ | BENIGN | ERROR | strict detection rate |
|------|---|-----------|-------------|--------|-------|----------------------|
| code | 1251 | 379 | 679 | 572 | 0 | 30.3% |
| benign | 49 | 0 | 7 | 42 | 0 | 0.0% |

## VsMex — FULL corpus (pessimistic bound)

> Every Microsoft-removed extension counted as malicious, including the ~47% removed for impersonation, copyright, spam or at the owner's request. Those bundles typically contain no hostile code, so this matrix charges the detector for failures that are out of its scope. Reported for completeness.

Samples: **3839**  ·  malicious-labelled: 3790  ·  benign-labelled: 49

### STRICT (positive = MALICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 863 | FN = 2927 |
| **Actual BENIGN**    | FP = 0 | TN = 49 |

Precision **100.0%** · Recall **22.8%** · F1 **37.1%** · Accuracy **23.8%** · MCC **0.061** · n = 3839

### TRIAGE (positive = MALICIOUS or SUSPICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 1611 | FN = 2179 |
| **Actual BENIGN**    | FP = 7 | TN = 42 |

Precision **99.6%** · Recall **42.5%** · F1 **59.6%** · Accuracy **43.1%** · MCC **0.064** · n = 3839

### Verdict distribution by evidence tier

| Tier | n | MALICIOUS | SUSPICIOUS+ | BENIGN | ERROR | strict detection rate |
|------|---|-----------|-------------|--------|-------|----------------------|
| suspect | 762 | 213 | 426 | 336 | 0 | 28.0% |
| policy | 1774 | 271 | 506 | 1268 | 0 | 15.3% |
| code | 1251 | 379 | 679 | 572 | 0 | 30.3% |
| unknown | 3 | 0 | 0 | 3 | 0 | 0.0% |
| benign | 49 | 0 | 7 | 42 | 0 | 0.0% |

### Detection rate by Microsoft removal reason

| Removal reason | n | MALICIOUS | flagged | strict rate | triage rate |
|----------------|---|-----------|---------|-------------|-------------|
| Impersonation | 1512 | 179 | 388 | 11.8% | 25.7% |
| Malware | 1122 | 326 | 596 | 29.1% | 53.1% |
| Untrustworthy | 762 | 213 | 426 | 28.0% | 55.9% |
| Spam | 174 | 87 | 95 | 50.0% | 54.6% |
| Malicious | 106 | 53 | 77 | 50.0% | 72.6% |
| impersonation | 56 | 1 | 15 | 1.8% | 26.8% |
| Copyright violation | 14 | 3 | 3 | 21.4% | 21.4% |
| Spam / Malware | 14 | 0 | 0 | 0.0% | 0.0% |
| Owner Request | 8 | 0 | 0 | 0.0% | 0.0% |
| Publisher requested | 6 | 1 | 5 | 16.7% | 83.3% |
| Impersonation;Malware | 5 | 0 | 5 | 0.0% | 100.0% |
| Potentially malicious | 4 | 0 | 1 | 0.0% | 25.0% |
| (none) | 3 | 0 | 0 | 0.0% | 0.0% |
| Deprecated | 2 | 0 | 0 | 0.0% | 0.0% |
| Typo-squatting | 1 | 0 | 0 | 0.0% | 0.0% |
| Expired domain | 1 | 0 | 0 | 0.0% | 0.0% |

## Combined (all corpora pooled)

> Both datasets together, every VsMex removal reason counted as malicious.

Samples: **3962**  ·  malicious-labelled: 3913  ·  benign-labelled: 49

### STRICT (positive = MALICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 917 | FN = 2996 |
| **Actual BENIGN**    | FP = 0 | TN = 49 |

Precision **100.0%** · Recall **23.4%** · F1 **38.0%** · Accuracy **24.4%** · MCC **0.061** · n = 3962

### TRIAGE (positive = MALICIOUS or SUSPICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 1674 | FN = 2239 |
| **Actual BENIGN**    | FP = 7 | TN = 42 |

Precision **99.6%** · Recall **42.8%** · F1 **59.8%** · Accuracy **43.3%** · MCC **0.064** · n = 3962

### Verdict distribution by evidence tier

| Tier | n | MALICIOUS | SUSPICIOUS+ | BENIGN | ERROR | strict detection rate |
|------|---|-----------|-------------|--------|-------|----------------------|
| code | 1374 | 433 | 742 | 632 | 0 | 31.5% |
| benign | 49 | 0 | 7 | 42 | 0 | 0.0% |
| suspect | 762 | 213 | 426 | 336 | 0 | 28.0% |
| policy | 1774 | 271 | 506 | 1268 | 0 | 15.3% |
| unknown | 3 | 0 | 0 | 3 | 0 | 0.0% |

## Corpus inventory

| Dataset | discovered | analysed | .vsix | unpacked dirs |
|---------|-----------|----------|-------|---------------|
| datadog-malicious | 123 | 123 | 123 | 0 |
| datadog-benign | 49 | 49 | 49 | 0 |
| vsmex | 3790 | 3790 | 3790 | 0 |
