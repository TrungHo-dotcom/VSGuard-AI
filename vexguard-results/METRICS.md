# VEXGuard — Evaluation Report

Generated: 2026-08-13T13:34:32.870Z
Engine: static 3.0.0 · sandbox 3.0.0 · orchestrator 3.0.0

## Decision rules

| Rule | Positive class | Use |
|------|----------------|-----|
| **STRICT** | verdict = MALICIOUS | auto-block / removal decisions |
| **TRIAGE** | verdict = MALICIOUS or SUSPICIOUS | analyst review queue |

## DataDog corpus (Dataset_Malicious + Dataset_Benign)

> Balanced ground truth from the corpus itself: every sample under the malicious tree is a confirmed malicious package, every sample under the benign tree is a top-installed marketplace extension. This is the primary precision/recall measurement.

Samples: **238**  ·  malicious-labelled: 138  ·  benign-labelled: 100

### STRICT (positive = MALICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 55 | FN = 83 |
| **Actual BENIGN**    | FP = 11 | TN = 89 |

Precision **83.3%** · Recall **39.9%** · F1 **53.9%** · Accuracy **60.5%** · MCC **0.318** · n = 238

### TRIAGE (positive = MALICIOUS or SUSPICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 68 | FN = 70 |
| **Actual BENIGN**    | FP = 39 | TN = 61 |

Precision **63.6%** · Recall **49.3%** · F1 **55.5%** · Accuracy **54.2%** · MCC **0.102** · n = 238

### Verdict distribution by evidence tier

| Tier | n | MALICIOUS | SUSPICIOUS+ | BENIGN | ERROR | strict detection rate |
|------|---|-----------|-------------|--------|-------|----------------------|
| code | 138 | 55 | 68 | 70 | 0 | 39.9% |
| benign | 100 | 11 | 39 | 61 | 0 | 11.0% |

## Combined (all corpora pooled)

> Both datasets together, every VsMex removal reason counted as malicious.

Samples: **238**  ·  malicious-labelled: 138  ·  benign-labelled: 100

### STRICT (positive = MALICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 55 | FN = 83 |
| **Actual BENIGN**    | FP = 11 | TN = 89 |

Precision **83.3%** · Recall **39.9%** · F1 **53.9%** · Accuracy **60.5%** · MCC **0.318** · n = 238

### TRIAGE (positive = MALICIOUS or SUSPICIOUS)

|              | Predicted POSITIVE | Predicted NEGATIVE |
|--------------|--------------------|--------------------|
| **Actual MALICIOUS** | TP = 68 | FN = 70 |
| **Actual BENIGN**    | FP = 39 | TN = 61 |

Precision **63.6%** · Recall **49.3%** · F1 **55.5%** · Accuracy **54.2%** · MCC **0.102** · n = 238

### Verdict distribution by evidence tier

| Tier | n | MALICIOUS | SUSPICIOUS+ | BENIGN | ERROR | strict detection rate |
|------|---|-----------|-------------|--------|-------|----------------------|
| code | 138 | 55 | 68 | 70 | 0 | 39.9% |
| benign | 100 | 11 | 39 | 61 | 0 | 11.0% |

## Corpus inventory

| Dataset | discovered | analysed | .vsix | unpacked dirs |
|---------|-----------|----------|-------|---------------|
| datadog-malicious | 138 | 138 | 134 | 4 |
| datadog-benign | 100 | 100 | 100 | 0 |
