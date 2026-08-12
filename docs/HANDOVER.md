# VEXGuard v3.1 — Research Handover

**Project:** CSN 304 — *Towards Identifying Malicious VS Code Extensions*
**Engine:** VEXGuard v3.1 (static + dynamic analysis of `.vsix` packages)
**Measurement date:** 2026-08-06
**Host:** Windows 11, Node v24.19.0, 12 cores, 8 analysis workers

---

## 0. Tóm tắt cho người đọc Việt (Vietnamese executive summary)

VEXGuard là engine phát hiện extension VS Code độc hại, gồm 2 tầng: **phân tích
tĩnh dựa trên AST** và **kích nổ động trong sandbox** có đồng hồ ảo (fast-forward
tới 366 ngày để phá bom hẹn giờ).

Kết quả đo trên **3.962 mẫu**, 0 lỗi phân tích:

* **0 dương tính giả (FP)** ở chế độ STRICT trên toàn bộ corpus → **Precision 100%**
* Bộ DataDog: **Recall 43,9%** (baseline cũ 40,0%, có 5 FP)
* VsMex tập code-level: **Recall 30,3%** (STRICT), **54,3%** (TRIAGE)

**Phát hiện quan trọng nhất:** VsMex **không phải** dataset mã độc — nó là dataset
*extension bị Microsoft gỡ bỏ*. Khoảng **47%** bị gỡ vì **mạo danh / spam / bản
quyền**, phần mã thường là bản sao y hệt extension gốc, **không có gì độc hại để
phát hiện**. Vì vậy báo cáo phải **tách tầng**, không được gộp thành một con số.

**Cảnh báo về độ tin cậy:** trong 2.996 trường hợp bỏ sót, chỉ **359 (12,0%)** có
nguyên nhân đã kiểm chứng chắc chắn. **88%** còn lại là **suy luận chưa kiểm
chứng** — xem mục 7.

---

## 1. What the engine does

For any `.vsix` or unpacked extension directory:

| Layer | Module | Function |
|---|---|---|
| 0 | `dataset.js` | Corpus ingestion, ground-truth resolution, evidence tiering |
| 1 | `preprocess.js` | AST-first static analysis (acorn), de-obfuscation, IOC scan |
| 2 | `sandbox.js` | Detonation in `vm.createContext()` with 11 hooked modules |
| 3 | `data-intel.js` | Closed-loop taint: proven read → send |
| 4 | `mock-vscode.js` | VS Code API simulation, 12 namespaces, 27 fireable events |
| 5 | `time-machine.js` | Virtual clock, 366-day fast-forward, non-blocking |
| — | `decoy-profile.js` | Synthetic victim profile (20 bait secrets) |
| — | `native-spoof.js` | `Function.prototype.toString` cloaking |
| — | `zip-util.js` | Dependency-free ZIP/VSIX reader |
| — | `benchmark.js` | Confusion matrices + root-cause reporting |

Verdict = `max(static, dynamic)`, plus **cross-modality corroboration**: when both
layers independently flag the same indicator family, two sub-threshold SUSPICIOUS
findings escalate to MALICIOUS.

---

## 2. Datasets

### 2.1 DataDog (`Dataset_Malicious/`, `Dataset_Benign/`)

```
<publisher>.<name>/<version>.vsix
<publisher>.<name>/<version>/extension/package.json    (some pre-unpacked)
Sample/Sample/<publisher>.<name>-<version>.vsix        (loose extras)
```

123 malicious `.vsix` + 49 benign controls (top-installed marketplace extensions).
Ground truth = the directory tree. This is the **primary precision/recall
measurement** because it is the only corpus with negatives.

### 2.2 VsMex (Alachkar et al., CODASPY '26, DOI 10.1145/3800506.3803487)

```
extensions/<publisher>.<name>/<version>/<publisher>.<name>-<version>.vsix
metadata/msft_vscode_flagged_extensions.csv    1,852 rows (per extension)
metadata/vsmex_metadata.csv                    3,791 rows (per version)
```

1,609 extensions, **3,790 `.vsix`** (3,777 distinct extension@version — 13
artefacts are filed under two directory names; 0.3%, documented, not a dedup bug).

**⚠ THE CRITICAL LABEL FINDING.** `msft_classification_type` records *why*
Microsoft removed the extension, not that its code is hostile:

| Tier | Reasons | Artefacts | % |
|---|---|---:|---:|
| **code** | Malware, Malicious, Potentially malicious, Spam/Malware, Impersonation;Malware | 1,251 | 33% |
| suspect | Untrustworthy | 762 | 20% |
| **policy** | Impersonation, Spam, Copyright, Owner Request, Deprecated, Typo-squatting, Expired domain | 1,774 | 47% |
| unknown | (absent from metadata) | 3 | <1% |

Measured detection rate by tier confirms the split is real:

| Tier | n | STRICT | TRIAGE |
|---|---:|---:|---:|
| code | 1,251 | **30.3%** | 54.3% |
| suspect | 762 | 28.0% | 55.9% |
| policy | 1,774 | **15.3%** | 28.5% |

A ~2× gap. Pooling all 1,852 extensions into one matrix charges the detector for
failures outside its design scope. **Always report stratified.**

---

## 3. Results — measured, 3,962 samples, 0 analysis errors

### 3.1 Verdict distribution

| Corpus | n | MALICIOUS | SUSPICIOUS | BENIGN | ERROR | timed out |
|---|---:|---:|---:|---:|---:|---:|
| DataDog malicious | 123 | 54 | 9 | 60 | 0 | 4 |
| DataDog benign | 49 | 0 | 7 | 42 | 0 | 0 |
| VsMex | 3,790 | 863 | 748 | 2,179 | 0 | 53 |

### 3.2 Confusion matrices

Two decision rules are reported side by side throughout:
**STRICT** = positive iff MALICIOUS (auto-block threshold).
**TRIAGE** = positive iff MALICIOUS or SUSPICIOUS (analyst queue).

**DataDog (n = 172)** — the headline result

| Rule | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 54 | **0** | 69 | 49 | **100.0%** | 43.9% | 61.0% | 59.9% | 0.427 |
| TRIAGE | 63 | 7 | 60 | 42 | 90.0% | 51.2% | 65.3% | 61.0% | 0.339 |

**VsMex CODE-LEVEL + benign controls (n = 1,300)** — primary VsMex result

| Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 379 | **0** | 872 | 49 | **100.0%** | 30.3% | 46.5% |
| TRIAGE | 679 | 7 | 572 | 42 | 99.0% | 54.3% | **70.1%** |

**VsMex FULL + benign controls (n = 3,839)** — pessimistic bound

| Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 863 | **0** | 2,927 | 49 | 100.0% | 22.8% | 37.1% |
| TRIAGE | 1,611 | 7 | 2,179 | 42 | 99.6% | 42.5% | 59.6% |

**All pooled (n = 3,962)**

| Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 917 | **0** | 2,996 | 49 | 100.0% | 23.4% | 38.0% |
| TRIAGE | 1,674 | 7 | 2,239 | 42 | 99.6% | 42.8% | 59.8% |

### 3.3 Comparison to the prior baseline (`DynamicAnalysisCode/FAILURES.md`)

| | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| v2 baseline | 48 | 5 | 72 | 44 | 90.6% | 40.0% | 55.5% | 54.4% |
| **v3.1 STRICT** | 54 | **0** | 69 | 49 | **100.0%** | 43.9% | 61.0% | 59.9% |

False positives eliminated (5 → 0); precision +9.4 pp; recall +3.9 pp; F1 +5.5 pp.

### 3.4 The 7 TRIAGE false positives (complete list)

All are SUSPICIOUS at score 35; **none reached MALICIOUS**:

```
donjayamanne.githistory                v0.6.20
golang.go                              v0.55.0
mhutchie.git-graph                     v1.30.0
ms-python.python                       v2026.5.2026061001
redhat.vscode-yaml                     v1.24.2026062009
streetsidesoftware.code-spell-checker  v4.6.0
TabNine.tabnine-vscode                 v3.335.0
```

Cause in every case: supporting-tier capability signals only (dynamic
`child_process` command construction, `machineId` telemetry read,
`installExtension` offer). No primary evidence of intent.

---

## 4. Root-cause breakdown of all 2,996 false negatives

| Cause | n | % | Engine defect? |
|---|---:|---:|---|
| `OUT_OF_SCOPE_POLICY_REMOVAL` | 1,482 | 49.5% | No — impersonation / spam / copyright |
| `OUT_OF_SCOPE_UNTRUSTWORTHY` | 530 | 17.7% | No — risk judgement, not malicious code |
| `DORMANT_NO_OBSERVABLE_PAYLOAD` | 429 | 14.3% | Partly — 0 events, 0 static IOC |
| `BELOW_MALICIOUS_THRESHOLD` | 307 | 10.2% | Tunable — all caught by TRIAGE |
| `RAN_BUT_UNRECOGNISED` | 106 | 3.5% | Yes — needs new rules |
| `NETWORK_ONLY_INDISTINGUISHABLE` | 58 | 1.9% | Hard residue — needs endpoint reputation |
| `TIMEOUT` | 52 | 1.7% | Operational — see §6 |
| `UNRECOGNISED_BEHAVIOUR` | 32 | 1.1% | Yes — needs new rules |

Of the 2,996: **757 are flagged SUSPICIOUS** (caught by TRIAGE), **2,239 missed
entirely**, 0 errors.

Full per-sample attribution: `vexguard-results/ROOT-CAUSE.md`.

---

## 5. How to reproduce

```bash
cd VEXGuard
npm install acorn          # required — without it the static layer degrades to regex
```

Prove the pipeline works (builds an OS-gated, 90-day time-bombed stealer and
detonates it end to end):

```bash
node VEXGuard.js --selftest
```

Full evaluation:

```bash
node benchmark.js --datasets all --concurrency 8 --timeout 120000
```

Useful flags: `--limit N` (smoke test), `--latest-only` (newest version per
extension), `--resume`, `--report-only`, `--tiers code`, `--exclude-tiers policy`,
`--static-only`.

Outputs land in `vexguard-results/`: `METRICS.md`, `ROOT-CAUSE.md`,
`metrics.json`, `results-<corpus>.csv`, `results-<corpus>.jsonl`.

Runtime: ~40 min for 3,962 samples at concurrency 8 on 12 cores.

---

## 6. Operational caveat — READ BEFORE CITING NUMBERS

**Every figure above comes from a 60-second per-sample timeout at concurrency 8.**
53 VsMex samples (1.4%) hit that cap, so their FN attribution reflects analysis
that was *cut short*, not analysis that completed and found nothing.

The 15 samples that newly hit the cap were re-run serially on an idle machine with
a 120 s cap:

```
completed within 120s: 12   still timing out: 3
```

Four of them return **SUSPICIOUS** when given time (`atomgit.atomcode-vscode@0.0.3`,
`openbase.openbase-vscode@10.3.2 / 10.3.3 / 10.3.4`). Three exceed even 120 s and
need investigation rather than a bigger budget:
`embeddteam.embeddedprojectmanager@0.0.2`,
`pedrocmota.workspace-formatter-multiple@1.0.0` and `@1.0.1`.

**Recommendation:** run the publication measurement at `--timeout 120000`.
Raising the cap recovers more detections than either detection feature added in
v3.1 (see §8).

---

## 7. ⚠ What is NOT verified — please do not overstate these

This section exists so the claims in §4 are not repeated as established fact.

1. **2,012 of 2,996 FNs (67%) are labelled "out of scope" purely from Microsoft's
   removal-reason field. The code was NOT manually inspected.** Microsoft can
   classify an extension as `Impersonation` while it *also* carries malware — the
   dataset contains explicit `Impersonation;Malware` rows, and 272 `policy`-tier
   samples were independently scored MALICIOUS by the engine. So the true count of
   "genuinely needs new detection rules" lies somewhere between **138** and
   **2,150**, not at 138.

2. **429 `DORMANT` samples: the observation is certain (0 events, 0 IOC), the
   explanation is not.** Three possibilities are indistinguishable with current
   evidence: (a) the version really is clean, (b) the payload is gated on a
   condition the simulator does not reproduce, (c) our simulation has a gap. Only
   **one** sample was manually verified (`ab-498.cppformat@1.0.8` — genuinely a
   working AStyle formatter). 428 unverified.

3. **138 `RAN_BUT_UNRECOGNISED` + `UNRECOGNISED_BEHAVIOUR`**: activity was
   observed but never confirmed to be malicious.

4. **Only 359 of 2,996 FNs (12.0%) have a verified cause** — 307
   `BELOW_MALICIOUS_THRESHOLD` (score recorded, provably sub-threshold) plus 52
   `TIMEOUT` (process demonstrably killed). The other **88%** is inference.

---

## 8. Known limitations of the approach

* **Impersonation is undetectable by construction.** It needs publisher reputation
  and marketplace metadata; this engine analyses bundles. 47% of VsMex.
* **AI-proxy extensions are behaviourally identical to AI malware.** The 20
  `sanchuan.*-copilot` samples route prompts to a third-party endpoint — exactly
  what a legitimate AI assistant does. Separating them needs endpoint reputation.
* **Server-side triggers.** A payload waiting on a live C2 response never fires in
  a mocked network.
* **Native binaries.** `.exe`/`.dll` shipped inside a VSIX are flagged as artefacts
  but never analysed.
* **Label granularity.** DataDog labels the *package*; a clean version of a flagged
  publisher counts as a miss.
* **v3.1's two new detection features changed no verdict on either corpus.** The
  shell-execution taint sink and document-content fuzzing are proven correct on
  targeted synthetic specimens (35 → 145 and a captured beacon respectively), but
  no sample in DataDog or VsMex exfiltrates via a command line or gates on document
  content. They close real gaps these corpora do not exercise. Do not report them
  as a metrics improvement.

---

## 9. Suggested next steps

1. **Re-run at `--timeout 120000`** and republish. Cheapest available recall gain.
2. **Manually triage a random sample of ~50 `policy`-tier misses** to put a real
   confidence interval on the "out of scope" claim in §7.1. This is the single
   highest-value experiment remaining.
3. **Investigate the 3 samples exceeding 120 s** — likely a runaway loop the
   Time Machine's interval cap does not bound.
4. **Add endpoint reputation** (domain age, registrar, passive DNS) to attack the
   58 `NETWORK_ONLY_INDISTINGUISHABLE` cases and the AI-proxy class.
5. **Route the 138 unrecognised-behaviour samples through an LLM verdict engine.**
   `VEXGuard.digest(evidence)` already emits a promptable summary, and both the
   verdict and forensic engines are swappable (`new VEXGuard({ verdictEngine })`).

---

## 10. File inventory

**Engine** — `VEXGuard.js`, `benchmark.js`, `dataset.js`, `preprocess.js`,
`sandbox.js`, `data-intel.js`, `mock-vscode.js`, `time-machine.js`,
`decoy-profile.js`, `native-spoof.js`, `zip-util.js`

**Launchers** — `Run-VEXGuard.ps1`, `VEXGuard_run.bat`, `package.json`

**Documentation**
| File | Contents |
|---|---|
| `VEXGuard.README.md` | Architecture, API, all CLI flags, environment knobs |
| `DATASETS.md` | Full structural analysis of both corpora |
| `CHANGES-v3.md` | Every change with the measured failure that motivated it |
| `HANDOVER.md` | This file |

**Results** — `vexguard-results/METRICS.md`, `ROOT-CAUSE.md`, `metrics.json`,
`results-datadog-malicious.csv`, `results-datadog-benign.csv`,
`results-vsmex.csv` (+ matching `.jsonl` evidence digests)

---

## 11. Reproducibility notes

* The engine has **one** external dependency: `acorn`. Everything else is Node
  built-ins, including ZIP extraction.
* Analysis is **process-isolated** — untrusted code runs in a child process inside
  `vm.createContext()` with every I/O module hooked. Writes are blocked, network is
  mocked, no process is ever spawned.
* `os.homedir()` and the Windows environment point at a **throw-away decoy
  profile**, so a stealer harvests fabricated secrets and never reaches the
  analyst's real keys. Every decoy value is structurally invalid. The profile is
  deleted after each run.
* **Do not run other CPU-heavy work during a benchmark.** Timeouts are sensitive to
  contention; measured runs differed by up to 15 samples purely from machine load.
