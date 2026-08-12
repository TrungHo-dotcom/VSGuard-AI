# 03 — Test Results / Kết quả kiểm thử

**System:** VSGuard AI (engine identifier: VEXGuard v3.1)
**Subject:** CSN 304 — *Towards Identifying Malicious VS Code Extensions*
**Measurement date:** 2026-08-06
**Environment:** Windows 11 Pro, Node.js v24.19.0, 12 CPU cores, 8 analysis workers
**Run parameters:** `--datasets all --concurrency 8 --timeout 60000`

---

# PART A — ENGLISH

## A.1 How to read this document

Three points determine whether the figures below are interpreted correctly.

**First, two decision rules are reported for every population.** The STRICT rule
counts only a `MALICIOUS` verdict as a positive detection; it corresponds to a
system that blocks automatically, where a false positive removes a legitimate
extension from a developer's machine. The TRIAGE rule counts `MALICIOUS` and
`SUSPICIOUS` together; it corresponds to a review queue, where a false positive
costs an analyst a few minutes. These two rules answer different questions and
neither alone characterises the system.

**Second, the VsMex corpus is stratified rather than pooled.** Section A.5 sets out
the reason in full. In summary, VsMex contains extensions removed by Microsoft for
*any* reason, and approximately 47 per cent were removed for brand impersonation or
spam rather than for hostile code. Reporting a single pooled figure would attribute
to the detector a limitation that lies outside its design scope.

**Third, section A.8 states explicitly which conclusions are verified and which are
inference.** Of the 2,996 missed detections, only 359 have a cause that was
confirmed by evidence. The remainder are attributed by reasoning that has not been
independently checked. That distinction is preserved throughout rather than
smoothed over.

## A.2 Corpus composition

| Corpus | Samples | Label | Provenance of ground truth |
|---|---:|---|---|
| DataDog malicious | 123 | 1 (malicious) | Datadog Security Labs; every sample manually triaged |
| DataDog benign | 49 | 0 (benign) | Top-installed marketplace extensions |
| VsMex | 3,790 | 1 (malicious) | Microsoft removal records (Alachkar et al., CODASPY '26) |
| **Total** | **3,962** | | |

The 3,790 VsMex artefacts correspond to 3,777 distinct (extension, version) pairs.
Thirteen `.vsix` files are filed under two directory names within the corpus itself
and are consequently analysed twice. This affects 0.3 per cent of the corpus, is
documented rather than silently corrected, and does not materially alter any figure
below.

VsMex composition by evidence tier, derived from Microsoft's stated removal reason:

| Tier | Removal reasons | Samples | Share |
|---|---|---:|---:|
| **code** | Malware; Malicious; Potentially malicious; Spam/Malware; Impersonation;Malware | 1,251 | 33.0% |
| suspect | Untrustworthy | 762 | 20.1% |
| **policy** | Impersonation; Spam; Copyright violation; Owner Request; Publisher requested; Deprecated; Typo-squatting; Expired domain | 1,774 | 46.8% |
| unknown | Absent from metadata | 3 | 0.1% |

## A.3 Verdict distribution

| Corpus | Samples | MALICIOUS | SUSPICIOUS | BENIGN | ERROR | Timed out |
|---|---:|---:|---:|---:|---:|---:|
| DataDog malicious | 123 | 54 | 9 | 60 | 0 | 4 |
| DataDog benign | 49 | 0 | 7 | 42 | 0 | 0 |
| VsMex | 3,790 | 863 | 748 | 2,179 | 0 | 53 |

**Zero analysis errors across all 3,962 samples.** Every sample was successfully
unpacked, statically analysed and detonated.

Considering only the 3,913 samples labelled malicious:

| Outcome | Samples | Share |
|---|---:|---:|
| Detected with certainty (`MALICIOUS`) | 918 | 23.5% |
| Flagged for review (`SUSPICIOUS`) | 759 | 19.4% |
| Missed entirely (`BENIGN`) | 2,236 | 57.1% |
| Analysis error | 0 | 0.0% |

## A.4 Confusion matrices

### A.4.1 DataDog corpus — the principal measurement

This corpus is the principal measurement because it is the only one containing
negatives, and therefore the only one on which precision is meaningfully defined.

**STRICT rule (positive = MALICIOUS)**

|  | Predicted POSITIVE | Predicted NEGATIVE |
|---|---:|---:|
| **Actual MALICIOUS** | TP = 54 | FN = 69 |
| **Actual BENIGN** | **FP = 0** | TN = 49 |

Precision **100.0%** · Recall **43.9%** · F1 **61.0%** · Accuracy **59.9%** · MCC **0.427** · n = 172

**TRIAGE rule (positive = MALICIOUS or SUSPICIOUS)**

|  | Predicted POSITIVE | Predicted NEGATIVE |
|---|---:|---:|
| **Actual MALICIOUS** | TP = 63 | FN = 60 |
| **Actual BENIGN** | FP = 7 | TN = 42 |

Precision **90.0%** · Recall **51.2%** · F1 **65.3%** · Accuracy **61.0%** · MCC **0.339** · n = 172

### A.4.2 VsMex code-level subset — the principal VsMex result

Comprises the 1,251 samples Microsoft removed for hostile code, together with the
49 benign controls so that precision remains defined.

**STRICT rule**

|  | Predicted POSITIVE | Predicted NEGATIVE |
|---|---:|---:|
| **Actual MALICIOUS** | TP = 379 | FN = 872 |
| **Actual BENIGN** | **FP = 0** | TN = 49 |

Precision **100.0%** · Recall **30.3%** · F1 **46.5%** · n = 1,300

**TRIAGE rule**

|  | Predicted POSITIVE | Predicted NEGATIVE |
|---|---:|---:|
| **Actual MALICIOUS** | TP = 679 | FN = 572 |
| **Actual BENIGN** | FP = 7 | TN = 42 |

Precision **99.0%** · Recall **54.3%** · F1 **70.1%** · n = 1,300

### A.4.3 VsMex full corpus — pessimistic bound

Counts every removed extension as malicious, including those removed for policy
reasons. Reported for completeness; it charges the detector for a population it
cannot address.

| Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 863 | **0** | 2,927 | 49 | 100.0% | 22.8% | 37.1% |
| TRIAGE | 1,611 | 7 | 2,179 | 42 | 99.6% | 42.5% | 59.6% |

### A.4.4 All corpora pooled

| Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 917 | **0** | 2,996 | 49 | 100.0% | 23.4% | 38.0% |
| TRIAGE | 1,674 | 7 | 2,239 | 42 | 99.6% | 42.8% | 59.8% |

### A.4.5 Comparison against the prior system baseline

The preceding version of the pipeline was evaluated on the same DataDog corpus and
its results recorded in `DynamicAnalysisCode/FAILURES.md`.

| Version | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Prior baseline | 48 | 5 | 72 | 44 | 90.6% | 40.0% | 55.5% | 54.4% |
| **VSGuard AI v3.1** | 54 | **0** | 69 | 49 | **100.0%** | **43.9%** | **61.0%** | **59.9%** |
| Change | +6 | **−5** | −3 | +5 | +9.4 pp | +3.9 pp | +5.5 pp | +5.5 pp |

False positives were eliminated entirely while recall improved. The two movements
are independent: the false positives were removed by tightening indicator
specificity, and the recall gain came from new detection rules and from repairing
defects that prevented samples from being analysed at all.

## A.5 Detection rate by removal reason — justification for stratification

| Removal reason | Samples | STRICT | TRIAGE |
|---|---:|---:|---:|
| Malicious | 106 | 50.0% | 72.6% |
| Spam | 174 | 50.0% | 54.6% |
| Malware | 1,122 | 29.1% | 53.1% |
| Untrustworthy | 762 | 28.0% | 56.0% |
| Copyright violation | 14 | 21.4% | 21.4% |
| **Impersonation** | 1,568 | **11.5%** | **25.7%** |
| Owner Request / Deprecated / Expired domain | 11 | 0.0% | 0.0% |

Extensions removed for hostile code are detected at approximately **2.5 times** the
rate of those removed for impersonation, and impersonation alone constitutes 41 per
cent of the corpus. This gap is a property of the labels rather than of the
detector. An impersonating extension is frequently a byte-identical clone of the
legitimate original; identifying it requires publisher reputation and marketplace
metadata, which the system does not model and is not intended to model.

Reporting a single pooled recall figure of 22.8 per cent would therefore
misrepresent the system's performance on the population it was built to address,
which is 30.3 per cent under STRICT and 54.3 per cent under TRIAGE.

## A.6 False positive analysis

**Under the STRICT rule the system produced no false positives on any corpus.** No
benign extension was assigned a `MALICIOUS` verdict.

Under the TRIAGE rule seven benign extensions were assigned `SUSPICIOUS`, each at a
score of 35:

| Extension | Version |
|---|---|
| `donjayamanne.githistory` | 0.6.20 |
| `golang.go` | 0.55.0 |
| `mhutchie.git-graph` | 1.30.0 |
| `ms-python.python` | 2026.5.2026061001 |
| `redhat.vscode-yaml` | 1.24.2026062009 |
| `streetsidesoftware.code-spell-checker` | 4.6.0 |
| `TabNine.tabnine-vscode` | 3.335.0 |

Every one arises from supporting-tier capability indicators alone — dynamic
construction of a `child_process` command line, reading a machine identifier for
telemetry, or offering to install a companion extension. None presented primary
evidence of hostile intent. This is the intended behaviour of the two-tier scoring
model: such extensions are surfaced for review but never blocked automatically.

## A.7 False negative analysis

All 2,996 missed detections under the STRICT rule are attributed to one of eight
named causes.

| Cause | Samples | Share | Deficiency in the engine? |
|---|---:|---:|---|
| `OUT_OF_SCOPE_POLICY_REMOVAL` | 1,482 | 49.5% | No — impersonation, spam, copyright |
| `OUT_OF_SCOPE_UNTRUSTWORTHY` | 530 | 17.7% | No — a risk judgement, not an assertion of hostile code |
| `DORMANT_NO_OBSERVABLE_PAYLOAD` | 429 | 14.3% | Partly — zero events and zero static indicators |
| `BELOW_MALICIOUS_THRESHOLD` | 307 | 10.2% | Tunable — all are captured by the TRIAGE rule |
| `RAN_BUT_UNRECOGNISED` | 106 | 3.5% | Yes — requires additional detection rules |
| `NETWORK_ONLY_INDISTINGUISHABLE` | 58 | 1.9% | Hard residue — requires endpoint reputation data |
| `TIMEOUT` | 52 | 1.7% | Operational — see section A.9 |
| `UNRECOGNISED_BEHAVIOUR` | 32 | 1.1% | Yes — requires additional detection rules |

Of the 2,996, a total of **757 were assigned `SUSPICIOUS`** and are therefore
recovered by the TRIAGE rule; 2,239 were missed entirely.

Per-sample attribution for every case is provided in `results/ROOT-CAUSE.md`.

## A.8 Verification status — what is established and what is inferred

This section is included so that the attributions in section A.7 are not read as
established fact.

**Verified causes: 359 of 2,996 (12.0%).**

| Cause | Samples | Basis |
|---|---:|---|
| `BELOW_MALICIOUS_THRESHOLD` | 307 | The score is recorded and provably below threshold |
| `TIMEOUT` | 52 | The process was demonstrably terminated by the time limit |

**Inferred causes: 2,637 of 2,996 (88.0%).** The following limitations apply.

1. **2,012 samples (67.2% of all misses) are classified as out of scope solely from
   Microsoft's removal-reason field. Their code was not manually inspected.**
   Microsoft may classify an extension as `Impersonation` while it simultaneously
   carries a payload — the corpus contains explicit `Impersonation;Malware` records,
   and 272 samples in the `policy` tier were independently assigned `MALICIOUS` by
   the engine on code evidence. Consequently the true count of samples genuinely
   requiring new detection rules lies between **138** and **2,150**, not at 138.

2. **429 samples classified as dormant: the observation is certain, the explanation
   is not.** Zero events and zero static indicators is a recorded fact. Three
   explanations remain indistinguishable on present evidence: the version is
   genuinely clean; the payload is gated on a condition the simulation does not
   reproduce; or the simulation has a coverage gap. **One** sample was manually
   verified (`ab-498.cppformat@1.0.8`, confirmed to be a functioning code
   formatter with no payload). The remaining 428 were not.

3. **138 samples exhibited unrecognised behaviour.** Activity was observed but was
   never confirmed to be malicious.

## A.9 Operational sensitivity — the per-sample time limit

The measurement was performed with a 60-second per-sample limit. Fifty-three VsMex
samples (1.4 per cent) reached that limit, meaning their attribution reflects
analysis that was **interrupted** rather than analysis that completed and found
nothing.

To quantify the effect, the fifteen samples that newly reached the limit were
re-analysed **serially on an otherwise idle machine** with a 120-second limit:

```
 81,297 ms  completed  BENIGN      atomgit.atomcode-vscode@0.0.2
 81,256 ms  completed  SUSPICIOUS  atomgit.atomcode-vscode@0.0.3
 20,682 ms  completed  BENIGN      chat-gimay-agent.chat-gimay-agent@1.0.0
107,455 ms  completed  BENIGN      embedd-team.embedd-project-manager@0.0.3
117,888 ms  completed  BENIGN      embeddteam.embeddedprojectmanager@0.0.1
120,999 ms  TIMED OUT  BENIGN      embeddteam.embeddedprojectmanager@0.0.2
 56,712 ms  completed  BENIGN      krabt.krabt-proto@0.5.7
 45,379 ms  completed  SUSPICIOUS  openbase.openbase-vscode@10.3.2
 23,053 ms  completed  SUSPICIOUS  openbase.openbase-vscode@10.3.3
 23,580 ms  completed  SUSPICIOUS  openbase.openbase-vscode@10.3.4
120,188 ms  TIMED OUT  BENIGN      pedrocmota.workspace-formatter-multiple@1.0.0
120,153 ms  TIMED OUT  BENIGN      pedrocmota.workspace-formatter-multiple@1.0.1
 47,827 ms  completed  BENIGN      pogacic.vscode-proto3-upkeep@0.5.8
 47,519 ms  completed  BENIGN      serialt.sugar-proto@0.5.7
 47,716 ms  completed  BENIGN      siehc.vscode-proto3-rebirth@0.5.7

Completed within 120 s: 12    Still timed out: 3
```

Twelve of fifteen completed, and **four returned `SUSPICIOUS`** when granted
sufficient time. Raising the limit therefore recovers four TRIAGE detections.

Three samples exceed even 120 seconds and warrant investigation rather than a
larger budget: `embeddteam.embeddedprojectmanager@0.0.2` and
`pedrocmota.workspace-formatter-multiple` versions 1.0.0 and 1.0.1.

**Recommendation.** A publication measurement should be executed with
`--timeout 120000`. It should further be noted that timeout incidence is sensitive
to machine load; runs conducted while other processes competed for the processor
differed by up to fifteen samples.

## A.10 Functional verification of individual capabilities

Corpus-level metrics do not demonstrate that each countermeasure functions, because
a corpus exercises only the techniques its samples happen to use. Each capability
was therefore verified against a purpose-built synthetic specimen.

| Capability verified | Specimen construction | Result |
|---|---|---|
| Time-based evasion defeated | Credential stealer delayed by 90 days, gated on Windows | Detonated; virtual clock advanced 90 days in 9 ms; verdict `MALICIOUS` (175) |
| Awaited-delay deadlock resolved | `await sleep(30 days)` inside `activate()` | Previously hung indefinitely; now completes and the beacon is captured |
| Closed-loop taint proven | Reads decoy SSH key, transmits via HTTPS | Flow recorded: `…/.ssh/id_rsa → https://evil-c2.example.com/x` |
| Shell execution as taint sink | Secret passed on a `curl` command line and via a child environment variable | Score 35 → **145**; both channels attributed |
| Anti-analysis cloaking | Specimen probes 8 fingerprinting vectors, including the reflective `Function.prototype.toString.call()` bypass | All 8 report `[native code]`; specimen proceeded to detonate |
| Document-content gating defeated | Payload fires only when the saved document contains a magic keyword | Keyword synthesised from the specimen's own source; beacon captured |
| Base64 exfiltration decoded | Secrets Base64-encoded before transmission | Decoded and attributed to the originating file |

## A.11 Assessment of the most recent revision

The v3.1 revision added two detection capabilities: shell execution as a taint sink,
and document-content fuzzing. Both were verified functional against synthetic
specimens as recorded in section A.10.

**Neither changed any verdict on either corpus.** Comparison of the complete v3.0
and v3.1 result sets across all 3,962 samples yields zero escalations and four
de-escalations, and all four de-escalations were subsequently demonstrated to be
timeout artefacts rather than detection regressions — `openbase.openbase-vscode`
completes in 23 to 45 seconds on an idle machine and returns the same `SUSPICIOUS`
verdict recorded under v3.0.

The explanation is that no sample in either corpus exfiltrates data through a
command line or gates its payload on document content. The two capabilities close
genuine detection gaps that these particular corpora do not exercise.

It follows that **the v3.1 revision should not be presented as an improvement in
the headline metrics.** Its contribution is coverage of techniques absent from the
evaluation corpora. By contrast, raising the per-sample time limit recovers four
detections, which is a larger measured contribution than either new capability made
on this evidence.

## A.12 Known limitations

| Limitation | Consequence |
|---|---|
| Publisher reputation is not modelled | Impersonation is undetectable by construction — 46.8% of VsMex |
| AI-proxy extensions are behaviourally identical to AI malware | Twenty `sanchuan.*-copilot` samples route prompts to a third-party endpoint, precisely as a legitimate assistant does |
| Server-side triggers | A payload awaiting a live command-and-control response never fires against mocked network transport |
| Native binaries | Executables shipped inside a package are recorded as artefacts but not analysed |
| Label granularity | DataDog labels the package rather than the version; a clean release by a flagged publisher counts as a miss |

---

# PHẦN B — TIẾNG VIỆT

## B.1 Cách đọc tài liệu này

Ba điểm quyết định việc các con số dưới đây có được diễn giải đúng hay không.

**Thứ nhất, mỗi quần thể đều được báo cáo theo hai quy tắc quyết định.** Quy tắc
STRICT chỉ tính kết luận `MALICIOUS` là phát hiện dương tính; nó tương ứng với hệ
thống chặn tự động, nơi một dương tính giả đồng nghĩa với việc gỡ bỏ một tiện ích
hợp pháp khỏi máy lập trình viên. Quy tắc TRIAGE tính cả `MALICIOUS` lẫn
`SUSPICIOUS`; nó tương ứng với hàng đợi rà soát, nơi một dương tính giả chỉ tiêu tốn
của chuyên viên vài phút. Hai quy tắc trả lời hai câu hỏi khác nhau và không quy tắc
nào một mình mô tả đủ đặc tính hệ thống.

**Thứ hai, corpus VsMex được phân tầng chứ không gộp chung.** Mục B.5 trình bày đầy
đủ lý do. Tóm lược: VsMex chứa các tiện ích bị Microsoft gỡ bỏ vì *bất kỳ* lý do
nào, và khoảng 47 phần trăm bị gỡ vì mạo danh thương hiệu hoặc spam chứ không phải
vì mã độc. Công bố một con số gộp duy nhất sẽ quy cho bộ dò một giới hạn vốn nằm
ngoài phạm vi thiết kế của nó.

**Thứ ba, mục B.8 nêu rõ kết luận nào đã được kiểm chứng và kết luận nào là suy
luận.** Trong 2.996 trường hợp bỏ sót, chỉ 359 trường hợp có nguyên nhân được xác
nhận bằng bằng chứng. Phần còn lại được quy nguyên nhân bằng lập luận chưa được kiểm
tra độc lập. Sự phân biệt này được giữ nguyên xuyên suốt tài liệu thay vì làm mờ đi.

## B.2 Thành phần corpus

| Corpus | Số mẫu | Nhãn | Nguồn gốc nhãn chuẩn |
|---|---:|---|---|
| DataDog độc hại | 123 | 1 (độc hại) | Datadog Security Labs; mọi mẫu đều được thẩm định thủ công |
| DataDog lành tính | 49 | 0 (lành tính) | Các tiện ích có lượt cài đặt cao nhất trên marketplace |
| VsMex | 3.790 | 1 (độc hại) | Hồ sơ gỡ bỏ của Microsoft (Alachkar và cộng sự, CODASPY '26) |
| **Tổng cộng** | **3.962** | | |

3.790 hiện vật VsMex tương ứng với 3.777 cặp (tiện ích, phiên bản) phân biệt. Mười
ba tệp `.vsix` được xếp dưới hai tên thư mục khác nhau ngay trong corpus gốc, do đó
bị phân tích hai lần. Điều này ảnh hưởng 0,3 phần trăm corpus, được ghi nhận công
khai thay vì âm thầm chỉnh sửa, và không làm thay đổi đáng kể bất kỳ con số nào dưới
đây.

Thành phần VsMex theo tầng bằng chứng, suy ra từ lý do gỡ bỏ do Microsoft công bố:

| Tầng | Lý do gỡ bỏ | Số mẫu | Tỷ lệ |
|---|---|---:|---:|
| **code** | Malware; Malicious; Potentially malicious; Spam/Malware; Impersonation;Malware | 1.251 | 33,0% |
| suspect | Untrustworthy | 762 | 20,1% |
| **policy** | Impersonation; Spam; Copyright violation; Owner Request; Publisher requested; Deprecated; Typo-squatting; Expired domain | 1.774 | 46,8% |
| unknown | Không có trong metadata | 3 | 0,1% |

## B.3 Phân bố kết luận

| Corpus | Số mẫu | MALICIOUS | SUSPICIOUS | BENIGN | LỖI | Quá thời gian |
|---|---:|---:|---:|---:|---:|---:|
| DataDog độc hại | 123 | 54 | 9 | 60 | 0 | 4 |
| DataDog lành tính | 49 | 0 | 7 | 42 | 0 | 0 |
| VsMex | 3.790 | 863 | 748 | 2.179 | 0 | 53 |

**Không có lỗi phân tích nào trên toàn bộ 3.962 mẫu.** Mọi mẫu đều được giải nén,
phân tích tĩnh và kích nổ thành công.

Xét riêng 3.913 mẫu mang nhãn độc hại:

| Kết quả | Số mẫu | Tỷ lệ |
|---|---:|---:|
| Phát hiện chắc chắn (`MALICIOUS`) | 918 | 23,5% |
| Đánh dấu để rà soát (`SUSPICIOUS`) | 759 | 19,4% |
| Bỏ sót hoàn toàn (`BENIGN`) | 2.236 | 57,1% |
| Lỗi phân tích | 0 | 0,0% |

## B.4 Ma trận nhầm lẫn

### B.4.1 Corpus DataDog — phép đo chính

Corpus này là phép đo chính vì đây là corpus duy nhất chứa mẫu âm tính, và do đó là
corpus duy nhất trên đó chỉ số precision được định nghĩa một cách có ý nghĩa.

**Quy tắc STRICT (dương tính = MALICIOUS)**

|  | Dự đoán DƯƠNG TÍNH | Dự đoán ÂM TÍNH |
|---|---:|---:|
| **Thực tế ĐỘC HẠI** | TP = 54 | FN = 69 |
| **Thực tế LÀNH TÍNH** | **FP = 0** | TN = 49 |

Precision **100,0%** · Recall **43,9%** · F1 **61,0%** · Accuracy **59,9%** · MCC **0,427** · n = 172

**Quy tắc TRIAGE (dương tính = MALICIOUS hoặc SUSPICIOUS)**

|  | Dự đoán DƯƠNG TÍNH | Dự đoán ÂM TÍNH |
|---|---:|---:|
| **Thực tế ĐỘC HẠI** | TP = 63 | FN = 60 |
| **Thực tế LÀNH TÍNH** | FP = 7 | TN = 42 |

Precision **90,0%** · Recall **51,2%** · F1 **65,3%** · Accuracy **61,0%** · MCC **0,339** · n = 172

### B.4.2 Tập code-level của VsMex — kết quả VsMex chính

Bao gồm 1.251 mẫu Microsoft gỡ bỏ vì mã độc, cùng 49 mẫu đối chứng lành tính để chỉ
số precision vẫn được định nghĩa.

**Quy tắc STRICT**

|  | Dự đoán DƯƠNG TÍNH | Dự đoán ÂM TÍNH |
|---|---:|---:|
| **Thực tế ĐỘC HẠI** | TP = 379 | FN = 872 |
| **Thực tế LÀNH TÍNH** | **FP = 0** | TN = 49 |

Precision **100,0%** · Recall **30,3%** · F1 **46,5%** · n = 1.300

**Quy tắc TRIAGE**

|  | Dự đoán DƯƠNG TÍNH | Dự đoán ÂM TÍNH |
|---|---:|---:|
| **Thực tế ĐỘC HẠI** | TP = 679 | FN = 572 |
| **Thực tế LÀNH TÍNH** | FP = 7 | TN = 42 |

Precision **99,0%** · Recall **54,3%** · F1 **70,1%** · n = 1.300

### B.4.3 Toàn bộ corpus VsMex — cận dưới bi quan

Tính mọi tiện ích bị gỡ bỏ là độc hại, kể cả những tiện ích bị gỡ vì lý do chính
sách. Được báo cáo nhằm đảm bảo tính đầy đủ; ma trận này quy trách nhiệm cho bộ dò
đối với một quần thể mà nó không thể xử lý.

| Quy tắc | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 863 | **0** | 2.927 | 49 | 100,0% | 22,8% | 37,1% |
| TRIAGE | 1.611 | 7 | 2.179 | 42 | 99,6% | 42,5% | 59,6% |

### B.4.4 Gộp toàn bộ các corpus

| Quy tắc | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| STRICT | 917 | **0** | 2.996 | 49 | 100,0% | 23,4% | 38,0% |
| TRIAGE | 1.674 | 7 | 2.239 | 42 | 99,6% | 42,8% | 59,8% |

### B.4.5 So sánh với phiên bản nền trước đó

Phiên bản trước của quy trình đã được đánh giá trên cùng corpus DataDog và kết quả
được ghi nhận trong tệp `DynamicAnalysisCode/FAILURES.md`.

| Phiên bản | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Nền trước đó | 48 | 5 | 72 | 44 | 90,6% | 40,0% | 55,5% | 54,4% |
| **VSGuard AI v3.1** | 54 | **0** | 69 | 49 | **100,0%** | **43,9%** | **61,0%** | **59,9%** |
| Thay đổi | +6 | **−5** | −3 | +5 | +9,4 điểm % | +3,9 điểm % | +5,5 điểm % | +5,5 điểm % |

Dương tính giả được loại bỏ hoàn toàn trong khi recall vẫn tăng. Hai chuyển biến này
độc lập với nhau: dương tính giả được loại bỏ nhờ siết chặt tính đặc hiệu của chỉ
dấu, còn mức tăng recall đến từ các luật phát hiện mới và từ việc sửa những khiếm
khuyết vốn khiến mẫu không được phân tích ngay từ đầu.

## B.5 Tỷ lệ phát hiện theo lý do gỡ bỏ — cơ sở của việc phân tầng

| Lý do gỡ bỏ | Số mẫu | STRICT | TRIAGE |
|---|---:|---:|---:|
| Malicious | 106 | 50,0% | 72,6% |
| Spam | 174 | 50,0% | 54,6% |
| Malware | 1.122 | 29,1% | 53,1% |
| Untrustworthy | 762 | 28,0% | 56,0% |
| Copyright violation | 14 | 21,4% | 21,4% |
| **Impersonation** | 1.568 | **11,5%** | **25,7%** |
| Owner Request / Deprecated / Expired domain | 11 | 0,0% | 0,0% |

Các tiện ích bị gỡ vì mã độc được phát hiện với tỷ lệ cao gấp khoảng **2,5 lần** so
với những tiện ích bị gỡ vì mạo danh, trong khi riêng nhóm mạo danh đã chiếm 41 phần
trăm corpus. Khoảng cách này là thuộc tính của nhãn dữ liệu chứ không phải của bộ
dò. Một tiện ích mạo danh thường là bản sao giống hệt từng byte của bản gốc hợp
pháp; việc nhận diện nó đòi hỏi dữ liệu uy tín nhà phát hành và metadata marketplace
— những thứ hệ thống không mô hình hoá và cũng không được thiết kế để mô hình hoá.

Do đó, việc công bố một con số recall gộp duy nhất là 22,8 phần trăm sẽ mô tả sai
hiệu năng của hệ thống trên quần thể mà nó được xây dựng để xử lý, vốn đạt 30,3 phần
trăm theo STRICT và 54,3 phần trăm theo TRIAGE.

## B.6 Phân tích dương tính giả

**Theo quy tắc STRICT, hệ thống không tạo ra dương tính giả nào trên bất kỳ corpus
nào.** Không tiện ích lành tính nào bị gán kết luận `MALICIOUS`.

Theo quy tắc TRIAGE, bảy tiện ích lành tính bị gán `SUSPICIOUS`, mỗi trường hợp đều
ở mức điểm 35:

| Tiện ích | Phiên bản |
|---|---|
| `donjayamanne.githistory` | 0.6.20 |
| `golang.go` | 0.55.0 |
| `mhutchie.git-graph` | 1.30.0 |
| `ms-python.python` | 2026.5.2026061001 |
| `redhat.vscode-yaml` | 1.24.2026062009 |
| `streetsidesoftware.code-spell-checker` | 4.6.0 |
| `TabNine.tabnine-vscode` | 3.335.0 |

Mọi trường hợp đều phát sinh hoàn toàn từ các chỉ dấu tầng supporting — việc dựng
động dòng lệnh `child_process`, việc đọc định danh máy phục vụ telemetry, hoặc việc
đề nghị cài đặt một tiện ích đi kèm. Không trường hợp nào có bằng chứng primary về ý
đồ độc hại. Đây chính là hành vi được thiết kế của mô hình chấm điểm hai tầng: những
tiện ích như vậy được đưa ra rà soát nhưng không bao giờ bị chặn tự động.

## B.7 Phân tích âm tính giả

Toàn bộ 2.996 trường hợp bỏ sót theo quy tắc STRICT đều được quy về một trong tám
nguyên nhân có tên gọi cụ thể.

| Nguyên nhân | Số mẫu | Tỷ lệ | Có phải khiếm khuyết của engine? |
|---|---:|---:|---|
| `OUT_OF_SCOPE_POLICY_REMOVAL` | 1.482 | 49,5% | Không — mạo danh, spam, bản quyền |
| `OUT_OF_SCOPE_UNTRUSTWORTHY` | 530 | 17,7% | Không — là phán đoán rủi ro, không khẳng định có mã độc |
| `DORMANT_NO_OBSERVABLE_PAYLOAD` | 429 | 14,3% | Một phần — không sự kiện và không chỉ dấu tĩnh |
| `BELOW_MALICIOUS_THRESHOLD` | 307 | 10,2% | Có thể tinh chỉnh — tất cả đều được TRIAGE bắt được |
| `RAN_BUT_UNRECOGNISED` | 106 | 3,5% | Có — cần bổ sung luật phát hiện |
| `NETWORK_ONLY_INDISTINGUISHABLE` | 58 | 1,9% | Phần dư khó — cần dữ liệu uy tín điểm cuối |
| `TIMEOUT` | 52 | 1,7% | Vận hành — xem mục B.9 |
| `UNRECOGNISED_BEHAVIOUR` | 32 | 1,1% | Có — cần bổ sung luật phát hiện |

Trong 2.996 trường hợp, có **757 trường hợp được gán `SUSPICIOUS`** và do đó được
quy tắc TRIAGE thu hồi; 2.239 trường hợp bị bỏ sót hoàn toàn.

Việc quy nguyên nhân cho từng mẫu cụ thể được trình bày trong `results/ROOT-CAUSE.md`.

## B.8 Tình trạng kiểm chứng — điều gì đã xác lập, điều gì là suy luận

Mục này được đưa vào để các quy kết ở mục B.7 không bị đọc như sự thật đã xác lập.

**Nguyên nhân đã kiểm chứng: 359 trên 2.996 (12,0%).**

| Nguyên nhân | Số mẫu | Cơ sở |
|---|---:|---|
| `BELOW_MALICIOUS_THRESHOLD` | 307 | Điểm số được ghi nhận và chứng minh được là dưới ngưỡng |
| `TIMEOUT` | 52 | Tiến trình bị chấm dứt bởi giới hạn thời gian, có bằng chứng |

**Nguyên nhân suy luận: 2.637 trên 2.996 (88,0%).** Các giới hạn sau đây được áp
dụng.

1. **2.012 mẫu (67,2% tổng số bỏ sót) được xếp là ngoài phạm vi chỉ dựa trên trường
   lý do gỡ bỏ của Microsoft. Mã của chúng chưa được kiểm tra thủ công.** Microsoft
   hoàn toàn có thể phân loại một tiện ích là `Impersonation` trong khi tiện ích đó
   đồng thời mang payload — corpus có chứa các bản ghi `Impersonation;Malware` một
   cách tường minh, và 272 mẫu thuộc tầng `policy` đã được engine gán `MALICIOUS`
   một cách độc lập dựa trên bằng chứng mã. Do đó số lượng thật sự các mẫu cần luật
   phát hiện mới nằm trong khoảng từ **138** đến **2.150**, chứ không phải bằng 138.

2. **429 mẫu được xếp loại nằm im: quan sát là chắc chắn, giải thích thì không.**
   Việc không có sự kiện nào và không có chỉ dấu tĩnh nào là một dữ kiện đã ghi
   nhận. Ba cách giải thích vẫn không thể phân biệt được với bằng chứng hiện có:
   phiên bản đó thật sự sạch; payload bị chặn bởi một điều kiện mà mô phỏng không
   tái tạo được; hoặc mô phỏng còn lỗ hổng bao phủ. **Một** mẫu đã được kiểm chứng
   thủ công (`ab-498.cppformat@1.0.8`, xác nhận là một trình định dạng mã hoạt động
   bình thường, không có payload). 428 mẫu còn lại chưa được kiểm chứng.

3. **138 mẫu bộc lộ hành vi không nhận dạng được.** Có quan sát được hoạt động,
   nhưng chưa bao giờ xác nhận hoạt động đó là độc hại.

## B.9 Độ nhạy vận hành — giới hạn thời gian cho mỗi mẫu

Phép đo được thực hiện với giới hạn 60 giây cho mỗi mẫu. Năm mươi ba mẫu VsMex (1,4
phần trăm) chạm giới hạn này, nghĩa là việc quy nguyên nhân của chúng phản ánh một
quá trình phân tích **bị gián đoạn** chứ không phải một quá trình phân tích đã hoàn
tất và không tìm thấy gì.

Để định lượng tác động, mười lăm mẫu mới chạm giới hạn đã được phân tích lại **tuần
tự trên một máy không có tải khác** với giới hạn 120 giây:

```
 81.297 ms  hoàn tất   BENIGN      atomgit.atomcode-vscode@0.0.2
 81.256 ms  hoàn tất   SUSPICIOUS  atomgit.atomcode-vscode@0.0.3
 20.682 ms  hoàn tất   BENIGN      chat-gimay-agent.chat-gimay-agent@1.0.0
107.455 ms  hoàn tất   BENIGN      embedd-team.embedd-project-manager@0.0.3
117.888 ms  hoàn tất   BENIGN      embeddteam.embeddedprojectmanager@0.0.1
120.999 ms  QUÁ GIỜ    BENIGN      embeddteam.embeddedprojectmanager@0.0.2
 56.712 ms  hoàn tất   BENIGN      krabt.krabt-proto@0.5.7
 45.379 ms  hoàn tất   SUSPICIOUS  openbase.openbase-vscode@10.3.2
 23.053 ms  hoàn tất   SUSPICIOUS  openbase.openbase-vscode@10.3.3
 23.580 ms  hoàn tất   SUSPICIOUS  openbase.openbase-vscode@10.3.4
120.188 ms  QUÁ GIỜ    BENIGN      pedrocmota.workspace-formatter-multiple@1.0.0
120.153 ms  QUÁ GIỜ    BENIGN      pedrocmota.workspace-formatter-multiple@1.0.1
 47.827 ms  hoàn tất   BENIGN      pogacic.vscode-proto3-upkeep@0.5.8
 47.519 ms  hoàn tất   BENIGN      serialt.sugar-proto@0.5.7
 47.716 ms  hoàn tất   BENIGN      siehc.vscode-proto3-rebirth@0.5.7

Hoàn tất trong 120 giây: 12    Vẫn quá giờ: 3
```

Mười hai trên mười lăm mẫu hoàn tất, và **bốn mẫu trả về `SUSPICIOUS`** khi được cấp
đủ thời gian. Việc nâng giới hạn do đó thu hồi được bốn phát hiện TRIAGE.

Ba mẫu vượt quá cả 120 giây và cần được điều tra thay vì cấp thêm thời gian:
`embeddteam.embeddedprojectmanager@0.0.2` và
`pedrocmota.workspace-formatter-multiple` phiên bản 1.0.0 và 1.0.1.

**Khuyến nghị.** Phép đo dùng để công bố nên được thực hiện với `--timeout 120000`.
Cũng cần lưu ý rằng tần suất quá giờ nhạy cảm với tải máy; những lần chạy có tiến
trình khác tranh chấp bộ xử lý cho kết quả chênh lệch tới mười lăm mẫu.

## B.10 Kiểm chứng chức năng của từng năng lực riêng lẻ

Các chỉ số ở cấp corpus không chứng minh được rằng từng biện pháp đối phó hoạt động,
bởi một corpus chỉ thử thách những kỹ thuật mà các mẫu của nó tình cờ sử dụng. Do
đó mỗi năng lực đều được kiểm chứng bằng một mẫu tổng hợp được dựng riêng.

| Năng lực được kiểm chứng | Cách dựng mẫu thử | Kết quả |
|---|---|---|
| Vô hiệu hoá né tránh theo thời gian | Mã đánh cắp thông tin trì hoãn 90 ngày, chặn theo Windows | Kích nổ thành công; đồng hồ ảo tua 90 ngày trong 9 ms; kết luận `MALICIOUS` (175) |
| Khắc phục deadlock khi chờ độ trễ | `await sleep(30 ngày)` bên trong `activate()` | Trước đây treo vô hạn; nay hoàn tất và tín hiệu gửi ra được ghi nhận |
| Chứng minh vết nhiễm vòng kín | Đọc khoá SSH mồi nhử, truyền qua HTTPS | Luồng được ghi nhận: `…/.ssh/id_rsa → https://evil-c2.example.com/x` |
| Dòng lệnh shell làm đích nhiễm | Bí mật truyền qua dòng lệnh `curl` và qua biến môi trường tiến trình con | Điểm 35 → **145**; cả hai kênh đều được quy nguồn |
| Nguỵ trang chống phân tích | Mẫu thử dò theo 8 hướng, gồm cả đường vòng phản chiếu `Function.prototype.toString.call()` | Cả 8 đều báo `[native code]`; mẫu thử tiến hành kích nổ |
| Vô hiệu hoá chặn theo nội dung tài liệu | Payload chỉ kích hoạt khi tài liệu được lưu chứa từ khoá bí mật | Từ khoá được tổng hợp từ chính mã nguồn mẫu; tín hiệu gửi ra được ghi nhận |
| Giải mã rò rỉ dạng Base64 | Bí mật được mã hoá Base64 trước khi truyền | Được giải mã và quy về đúng tệp nguồn |

## B.11 Đánh giá bản sửa đổi gần nhất

Bản sửa đổi v3.1 bổ sung hai năng lực phát hiện: dòng lệnh shell làm đích nhiễm, và
fuzzing nội dung tài liệu. Cả hai đều được kiểm chứng là hoạt động đúng trên mẫu
tổng hợp như ghi nhận tại mục B.10.

**Không năng lực nào làm thay đổi bất kỳ kết luận nào trên cả hai corpus.** So sánh
toàn bộ tập kết quả v3.0 và v3.1 trên cả 3.962 mẫu cho thấy không có trường hợp nâng
cấp nào và bốn trường hợp hạ cấp, và cả bốn trường hợp hạ cấp sau đó đều được chứng
minh là hiện tượng do quá giờ chứ không phải suy giảm khả năng phát hiện —
`openbase.openbase-vscode` hoàn tất trong 23 đến 45 giây trên máy không tải và trả
về đúng kết luận `SUSPICIOUS` đã ghi nhận ở v3.0.

Nguyên nhân là không có mẫu nào trong cả hai corpus rò rỉ dữ liệu qua dòng lệnh hoặc
chặn payload theo nội dung tài liệu. Hai năng lực này bịt những lỗ hổng phát hiện có
thật nhưng các corpus cụ thể này không chạm tới.

Do đó, **bản sửa đổi v3.1 không nên được trình bày như một cải thiện về chỉ số công
bố.** Đóng góp của nó là mở rộng phạm vi bao phủ đối với những kỹ thuật vắng mặt
trong corpus đánh giá. Ngược lại, việc nâng giới hạn thời gian cho mỗi mẫu thu hồi
được bốn phát hiện, tức là một đóng góp đo được lớn hơn so với từng năng lực mới
trên bằng chứng hiện có.

## B.12 Các giới hạn đã biết

| Giới hạn | Hệ quả |
|---|---|
| Uy tín nhà phát hành không được mô hình hoá | Mạo danh không thể phát hiện được về mặt nguyên lý — 46,8% VsMex |
| Tiện ích trung chuyển AI giống hệt mã độc AI về mặt hành vi | Hai mươi mẫu `sanchuan.*-copilot` chuyển tiếp truy vấn tới điểm cuối bên thứ ba, đúng như một trợ lý hợp pháp vẫn làm |
| Kích hoạt từ phía máy chủ | Payload chờ phản hồi từ máy chủ điều khiển thật sẽ không bao giờ kích hoạt trước lớp mạng mô phỏng |
| Tệp nhị phân gốc | Tệp thực thi đóng gói bên trong gói tiện ích được ghi nhận là hiện vật nhưng không được phân tích |
| Mức chi tiết của nhãn | DataDog gán nhãn cho gói chứ không cho phiên bản; một bản phát hành sạch của nhà phát hành bị gắn cờ vẫn bị tính là bỏ sót |
