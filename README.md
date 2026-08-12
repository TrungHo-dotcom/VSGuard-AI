# VSGuard AI — Evaluation Package

**Subject:** CSN 304 — *Towards Identifying Malicious VS Code Extensions*
**Engine identifier:** VEXGuard v3.1
**Package date:** 2026-08-06

---

# PART A — ENGLISH

## A.1 Contents of this package

This package is self-contained. It includes the complete detection engine, its
single external dependency, launch scripts, full documentation, and the measured
results of the most recent evaluation run.

```
VSGuard AI/
│
├── README.md                    ← this file; start here
│
├── docs/
│   ├── 01-SYSTEM-STRUCTURE.md   System architecture          [EN + VN]
│   ├── 02-WORKFLOW.md           Operational workflow         [EN + VN]
│   ├── 03-TEST-RESULTS.md       Evaluation results           [EN + VN]
│   ├── DATASETS.md              Corpus structural analysis   [EN]
│   ├── CHANGES-v3.md            Change log with rationale    [EN]
│   ├── ENGINE-REFERENCE.md      API and CLI reference        [EN]
│   └── HANDOVER.md              Research handover summary    [EN + VN summary]
│
├── results/
│   ├── METRICS.md               Generated confusion matrices
│   ├── ROOT-CAUSE.md            Per-sample diagnosis of every FP and FN
│   ├── metrics.json             Machine-readable metrics
│   ├── results-datadog-malicious.csv    123 rows
│   ├── results-datadog-benign.csv        49 rows
│   ├── results-vsmex.csv              3,790 rows
│   └── *.jsonl                  Per-sample evidence digests
│
├── node_modules/acorn/          Bundled AST parser (the only dependency)
│
├── VEXGuard.js                  Orchestrator and command-line interface
├── benchmark.js                 Evaluation driver
├── dataset.js                   Layer 0 — corpus ingestion
├── preprocess.js                Layer 1 — static analysis
├── sandbox.js                   Layer 2 — dynamic detonation
├── data-intel.js                Layer 3 — taint tracking
├── mock-vscode.js               Layer 4 — VS Code API simulation
├── time-machine.js              Layer 5 — virtual clock
├── decoy-profile.js             Synthetic victim profile
├── native-spoof.js              Anti-analysis cloaking
├── zip-util.js                  ZIP/VSIX container reader
├── package.json                 Manifest and npm scripts
├── Run-VEXGuard.ps1             PowerShell launcher
└── VEXGuard_run.bat             Batch launcher
```

Source code and all inline comments are written in English. The three principal
documents (01, 02, 03) are presented in both English and Vietnamese.

## A.2 Suggested reading order

| Order | Document | Purpose |
|:---:|---|---|
| 1 | `docs/01-SYSTEM-STRUCTURE.md` | What the system is and how it is composed |
| 2 | `docs/02-WORKFLOW.md` | How a sample proceeds through the pipeline |
| 3 | `docs/03-TEST-RESULTS.md` | What the system achieved, and its limits |
| 4 | `results/METRICS.md` | Machine-generated matrices confirming document 03 |
| 5 | `results/ROOT-CAUSE.md` | Individual diagnosis of every misclassification |

## A.3 Requirements

* **Node.js version 18 or later.** Verify with `node --version`.
* No further installation is required. The single external dependency, `acorn`,
  is bundled in `node_modules/`.
* No internet connection is required.

## A.4 Verifying the system on a new machine

The following command constructs a synthetic malicious extension — one that is
gated on the Windows operating system and delays its payload by ninety days — then
detonates it and asserts that both the outbound beacon and the proven data flow
were captured. It requires no dataset.

```
cd "VSGuard AI"
node VEXGuard.js --selftest
```

Expected output:

```
[selftest] verdict=MALICIOUS score=175 beacon=true provenTaintFlow=true
[selftest] flow: ssh_private_key  ...\.ssh\id_rsa → https://evil-c2.example.com/x
SELFTEST PASS — OS-gated, 90-day time-bombed stealer detonated, exfil proven end-to-end.
```

A `SELFTEST PASS` line confirms that all six analysis layers are operational.

Alternatively, `VEXGuard_run.bat selftest` performs the same check.

## A.5 Analysing a single extension

```
node VEXGuard.js <path-to-extension.vsix>
```

The system prints a verdict together with a forensic report mapped to MITRE ATT&CK
techniques.

## A.6 Reproducing the full evaluation

Reproduction requires the two research corpora, which are **not** included in this
package because of their size (several gigabytes). They are expected at the
following locations relative to the package's parent directory:

```
<parent>/Dataset_Malicious/     DataDog malicious corpus    (123 samples)
<parent>/Dataset_Benign/        DataDog benign controls      (49 samples)
<parent>/vsmex-dataset/         VsMex corpus              (3,790 samples)
<parent>/VSGuard AI/            this package
```

With the corpora present:

```
node benchmark.js --datasets all --concurrency 8 --timeout 120000
```

Approximate duration: forty minutes for 3,962 samples at concurrency 8 on twelve
processor cores. Results are written to `results/`.

For a short verification run limited to twenty samples per corpus:

```
node benchmark.js --datasets all --limit 20 --concurrency 8
```

The `results/` directory already contains the output of the completed evaluation,
so the reported figures may be examined without re-running the analysis.

## A.7 Summary of results

Measured across 3,962 samples with zero analysis errors:

| Population | Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DataDog (n = 172) | STRICT | 54 | **0** | 69 | 49 | **100.0%** | 43.9% | 61.0% |
| DataDog | TRIAGE | 63 | 7 | 60 | 42 | 90.0% | 51.2% | 65.3% |
| VsMex code-level (n = 1,300) | STRICT | 379 | **0** | 872 | 49 | **100.0%** | 30.3% | 46.5% |
| VsMex code-level | TRIAGE | 679 | 7 | 572 | 42 | 99.0% | 54.3% | **70.1%** |

Against the prior system baseline on the DataDog corpus: false positives reduced
from five to zero, precision improved from 90.6 to 100.0 per cent, recall from 40.0
to 43.9 per cent, and F1 from 55.5 to 61.0 per cent.

Document `03-TEST-RESULTS.md` presents the complete results, including the
stratification rationale for the VsMex corpus and an explicit statement of which
conclusions are verified and which are inferred.

## A.8 Safety of execution

The system analyses live malware. The following containment properties apply.

* Untrusted code executes in a **child process**, inside `vm.createContext()`, with
  every input/output module instrumented.
* File writes are intercepted and discarded; no file is written to disk.
* Network calls are answered by mocks; **no traffic leaves the host**.
* No operating-system process is ever created.
* `os.homedir()` and the Windows environment variables are redirected to a
  **disposable decoy profile**, so a credential stealer harvests fabricated secrets
  and never reaches genuine keys belonging to the operator. Every decoy value is
  structurally invalid and authenticates against no service. The profile is deleted
  after each run.

Executing `--selftest` or analysing a sample is therefore safe on an ordinary
workstation.

---

# PHẦN B — TIẾNG VIỆT

## B.1 Nội dung gói tài liệu

Gói này là gói khép kín. Nó bao gồm toàn bộ engine phát hiện, thư viện phụ thuộc duy
nhất, các script khởi chạy, tài liệu đầy đủ, và kết quả đo của lần đánh giá gần nhất.

```
VSGuard AI/
│
├── README.md                    ← tệp này; bắt đầu từ đây
│
├── docs/
│   ├── 01-SYSTEM-STRUCTURE.md   Kiến trúc hệ thống           [Anh + Việt]
│   ├── 02-WORKFLOW.md           Quy trình vận hành           [Anh + Việt]
│   ├── 03-TEST-RESULTS.md       Kết quả đánh giá             [Anh + Việt]
│   ├── DATASETS.md              Phân tích cấu trúc corpus    [Anh]
│   ├── CHANGES-v3.md            Nhật ký thay đổi kèm lý do   [Anh]
│   ├── ENGINE-REFERENCE.md      Tham chiếu API và CLI        [Anh]
│   └── HANDOVER.md              Tóm tắt bàn giao nghiên cứu  [Anh + tóm tắt Việt]
│
├── results/
│   ├── METRICS.md               Ma trận nhầm lẫn sinh tự động
│   ├── ROOT-CAUSE.md            Chẩn đoán từng mẫu FP và FN
│   ├── metrics.json             Số liệu dạng máy đọc được
│   ├── results-datadog-malicious.csv    123 dòng
│   ├── results-datadog-benign.csv        49 dòng
│   ├── results-vsmex.csv              3.790 dòng
│   └── *.jsonl                  Bản tóm lược bằng chứng từng mẫu
│
├── node_modules/acorn/          Bộ phân tích AST đóng gói kèm (phụ thuộc duy nhất)
│
├── VEXGuard.js                  Bộ điều phối và giao diện dòng lệnh
├── benchmark.js                 Trình đánh giá
├── dataset.js                   Tầng 0 — nạp corpus
├── preprocess.js                Tầng 1 — phân tích tĩnh
├── sandbox.js                   Tầng 2 — kích nổ động
├── data-intel.js                Tầng 3 — theo vết dữ liệu
├── mock-vscode.js               Tầng 4 — mô phỏng API VS Code
├── time-machine.js              Tầng 5 — đồng hồ ảo
├── decoy-profile.js             Hồ sơ nạn nhân giả
├── native-spoof.js              Nguỵ trang chống phân tích
├── zip-util.js                  Bộ đọc container ZIP/VSIX
├── package.json                 Tệp kê khai và script npm
├── Run-VEXGuard.ps1             Trình khởi chạy PowerShell
└── VEXGuard_run.bat             Trình khởi chạy Batch
```

Mã nguồn và toàn bộ chú thích trong mã được viết bằng tiếng Anh. Ba tài liệu chính
(01, 02, 03) được trình bày song ngữ Anh — Việt.

## B.2 Thứ tự đọc đề xuất

| Thứ tự | Tài liệu | Mục đích |
|:---:|---|---|
| 1 | `docs/01-SYSTEM-STRUCTURE.md` | Hệ thống là gì và được cấu thành ra sao |
| 2 | `docs/02-WORKFLOW.md` | Một mẫu đi qua quy trình như thế nào |
| 3 | `docs/03-TEST-RESULTS.md` | Hệ thống đạt được gì, và giới hạn ở đâu |
| 4 | `results/METRICS.md` | Ma trận sinh tự động, xác nhận tài liệu 03 |
| 5 | `results/ROOT-CAUSE.md` | Chẩn đoán riêng cho từng trường hợp phân loại sai |

## B.3 Yêu cầu hệ thống

* **Node.js phiên bản 18 trở lên.** Kiểm tra bằng lệnh `node --version`.
* Không cần cài đặt thêm. Thư viện phụ thuộc duy nhất là `acorn` đã được đóng gói
  sẵn trong `node_modules/`.
* Không cần kết nối Internet.

## B.4 Kiểm chứng hệ thống trên máy mới

Lệnh sau đây dựng một tiện ích độc hại tổng hợp — loại có chặn theo hệ điều hành
Windows và trì hoãn payload chín mươi ngày — sau đó kích nổ nó và khẳng định rằng cả
tín hiệu gửi ra lẫn luồng dữ liệu đã được chứng minh đều được ghi nhận. Lệnh này
không cần bộ dữ liệu nào.

```
cd "VSGuard AI"
node VEXGuard.js --selftest
```

Kết quả mong đợi:

```
[selftest] verdict=MALICIOUS score=175 beacon=true provenTaintFlow=true
[selftest] flow: ssh_private_key  ...\.ssh\id_rsa → https://evil-c2.example.com/x
SELFTEST PASS — OS-gated, 90-day time-bombed stealer detonated, exfil proven end-to-end.
```

Dòng `SELFTEST PASS` xác nhận cả sáu tầng phân tích đều hoạt động.

Ngoài ra, lệnh `VEXGuard_run.bat selftest` thực hiện cùng phép kiểm tra này.

## B.5 Phân tích một tiện ích đơn lẻ

```
node VEXGuard.js <đường-dẫn-tới-tiện-ích.vsix>
```

Hệ thống in ra kết luận kèm báo cáo pháp chứng ánh xạ theo kỹ thuật MITRE ATT&CK.

## B.6 Tái lập toàn bộ quá trình đánh giá

Việc tái lập đòi hỏi hai corpus nghiên cứu, vốn **không** được kèm trong gói này do
kích thước lớn (vài gigabyte). Chúng được kỳ vọng nằm tại các vị trí sau, tính tương
đối so với thư mục cha của gói:

```
<thư-mục-cha>/Dataset_Malicious/     Corpus độc hại DataDog     (123 mẫu)
<thư-mục-cha>/Dataset_Benign/        Đối chứng lành tính DataDog  (49 mẫu)
<thư-mục-cha>/vsmex-dataset/         Corpus VsMex             (3.790 mẫu)
<thư-mục-cha>/VSGuard AI/            gói này
```

Khi đã có đủ corpus:

```
node benchmark.js --datasets all --concurrency 8 --timeout 120000
```

Thời lượng ước tính: khoảng bốn mươi phút cho 3.962 mẫu ở mức song song 8 trên mười
hai nhân xử lý. Kết quả được ghi vào thư mục `results/`.

Để chạy kiểm chứng ngắn giới hạn hai mươi mẫu mỗi corpus:

```
node benchmark.js --datasets all --limit 20 --concurrency 8
```

Thư mục `results/` đã sẵn chứa kết quả của lần đánh giá đã hoàn tất, do đó các số
liệu được báo cáo có thể được xem xét mà không cần chạy lại quá trình phân tích.

## B.7 Tóm tắt kết quả

Đo trên 3.962 mẫu với không một lỗi phân tích nào:

| Quần thể | Quy tắc | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DataDog (n = 172) | STRICT | 54 | **0** | 69 | 49 | **100,0%** | 43,9% | 61,0% |
| DataDog | TRIAGE | 63 | 7 | 60 | 42 | 90,0% | 51,2% | 65,3% |
| VsMex tầng code (n = 1.300) | STRICT | 379 | **0** | 872 | 49 | **100,0%** | 30,3% | 46,5% |
| VsMex tầng code | TRIAGE | 679 | 7 | 572 | 42 | 99,0% | 54,3% | **70,1%** |

So với phiên bản nền trước đó trên corpus DataDog: dương tính giả giảm từ năm xuống
không, precision tăng từ 90,6 lên 100,0 phần trăm, recall tăng từ 40,0 lên 43,9 phần
trăm, và F1 tăng từ 55,5 lên 61,0 phần trăm.

Tài liệu `03-TEST-RESULTS.md` trình bày kết quả đầy đủ, bao gồm cơ sở lý luận của
việc phân tầng corpus VsMex và tuyên bố tường minh về việc kết luận nào đã được kiểm
chứng, kết luận nào là suy luận.

## B.8 An toàn khi thực thi

Hệ thống phân tích mã độc thật. Các đặc tính cách ly sau đây được áp dụng.

* Mã không tin cậy thực thi trong một **tiến trình con**, bên trong
  `vm.createContext()`, với mọi mô-đun vào/ra đều được giám sát.
* Thao tác ghi tệp bị chặn và huỷ bỏ; không tệp nào được ghi xuống đĩa.
* Lời gọi mạng được trả lời bằng mô phỏng; **không có lưu lượng nào rời khỏi máy**.
* Không tiến trình hệ điều hành nào được tạo ra.
* `os.homedir()` và các biến môi trường Windows được chuyển hướng tới một **hồ sơ
  mồi nhử dùng một lần**, nên mã đánh cắp thông tin chỉ thu được các bí mật giả và
  không bao giờ chạm tới khoá thật của người vận hành. Mọi giá trị mồi nhử đều không
  hợp lệ về cấu trúc và không xác thực được với bất kỳ dịch vụ nào. Hồ sơ bị xoá sau
  mỗi lần chạy.

Do đó, việc chạy `--selftest` hoặc phân tích một mẫu là an toàn trên máy trạm thông
thường.
