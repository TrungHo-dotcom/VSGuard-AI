# 01 — System Structure / Cấu trúc hệ thống

**System:** VSGuard AI (engine identifier: VEXGuard v3.1)
**Subject:** CSN 304 — *Towards Identifying Malicious VS Code Extensions*
**Document date:** 2026-08-06

---

# PART A — ENGLISH

## A.1 Purpose

VSGuard AI is a hybrid static–dynamic analysis engine that determines whether a
Visual Studio Code extension package (`.vsix`) is malicious. The system accepts
either a packaged `.vsix` archive or an unpacked extension directory, and produces
an explainable verdict together with a forensic report mapped to MITRE ATT&CK
techniques.

The system is designed for two distinct operating points. The **STRICT** decision
rule treats only a `MALICIOUS` verdict as positive and is intended for automated
blocking. The **TRIAGE** decision rule treats both `MALICIOUS` and `SUSPICIOUS` as
positive and is intended for an analyst review queue. Both are reported together
throughout, because reporting either in isolation misrepresents the system's
operating characteristics.

## A.2 Layered architecture

The engine is organised into six analysis layers plus three support modules.

| Layer | Module | Responsibility |
|:---:|---|---|
| 0 | `dataset.js` | Corpus ingestion, ground-truth resolution, evidence tiering |
| 1 | `preprocess.js` | Static analysis: AST parsing, de-obfuscation, IOC matching |
| 2 | `sandbox.js` | Dynamic detonation inside an instrumented virtual machine |
| 3 | `data-intel.js` | Sensitive-data classification and closed-loop taint tracking |
| 4 | `mock-vscode.js` | Simulation of the Visual Studio Code extension API |
| 5 | `time-machine.js` | Virtual clock permitting fast-forward through time-based evasion |
| — | `decoy-profile.js` | Synthetic victim profile supplying bait credentials |
| — | `native-spoof.js` | Anti-analysis cloaking of instrumented functions |
| — | `zip-util.js` | Dependency-free ZIP/VSIX container reader |

Orchestration and evaluation are handled by two further modules:

| Module | Responsibility |
|---|---|
| `VEXGuard.js` | Orchestrator, verdict engine, batch runner, command-line interface |
| `benchmark.js` | Evaluation driver producing confusion matrices and root-cause reports |

## A.3 Module specifications

### Layer 0 — `dataset.js` (Ingestion)

Recognises two corpus layouts automatically and resolves the ground-truth label
for each sample.

* **DataDog layout** — `<publisher>.<name>/<version>.vsix`, optionally accompanied
  by a pre-extracted `<version>/extension/` tree. The label derives from the
  directory tree in which the sample resides.
* **VsMex layout** — `extensions/<publisher>.<name>/<version>/<file>.vsix`, with
  labels resolved from two metadata files against Microsoft's own removal reason.

Three invariants govern ingestion:

1. Directories named `node_modules` are never traversed during **sample
   discovery**. A single extension may bundle thousands of nested `package.json`
   files; treating each as a distinct sample inflates the corpus and repeats work.
   The static layer still *reads* inside `node_modules`, since supply-chain
   trojans hide there — the exclusion governs what constitutes a sample, not what
   is scanned.
2. Where a sample exists both as a `.vsix` archive and as a pre-extracted
   directory, the archive takes precedence. Extracted trees may retain
   `execution-log.json` and `static-analysis.json` artefacts from earlier runs.
3. Each sample receives an **evidence tier** derived from its classification —
   `code`, `suspect`, `policy`, or `unknown`. Section A.6 explains the necessity
   of this field.

### Layer 1 — `preprocess.js` (Static analysis)

Parses each JavaScript file to an Abstract Syntax Tree using `acorn`, and judges
the *shape* of constructs rather than the presence of keywords.

| Construct | Basis of judgement |
|---|---|
| `eval()` / `new Function()` | The nature of the argument. Static literals and parenthesised JSON forms are ignored; only evaluation of decoded data is decisive. |
| `child_process.*` | Whether the command argument is static. A static command is ordinary tooling; a decoded command is a loader. |
| File writes | The destination. Writes to temporary directories, extension storage or `.vscode` are ignored; writes of executables or to autostart locations are flagged. |
| Download-and-execute cradle | Requires an interpreter, a remote payload reference, and an execution verb **within one string literal**. |

Indicators are separated into two tiers:

* **PRIMARY** indicators assert hostile intent independently. A `MALICIOUS`
  static verdict requires a primary score of at least 45.
* **SUPPORTING** indicators denote capability rather than intent. Their combined
  contribution is capped at 35 points, so an accumulation of capabilities can
  never reach a `MALICIOUS` verdict unaided.

The module currently carries 17 indicator-of-compromise families, three
reconnaissance command lists separated by intent level, and a set of AST-driven
call-shape rules.

### Layer 2 — `sandbox.js` (Dynamic detonation)

Executes the extension inside `vm.createContext()` with eleven instrumented
modules: `vscode`, `child_process`, `http`, `https`, `fs`, `fs/promises`, `os`,
`net`, `dns`, `crypto`, and `axios`.

Containment properties:

* File writes are intercepted and discarded.
* Network calls are answered by mocks; no traffic leaves the host.
* No operating-system process is ever created.
* Execution occurs in a child process, providing operating-system level isolation
  in addition to the virtual machine boundary.

Evasion countermeasures:

| Evasion technique | Countermeasure |
|---|---|
| Operating-system gating | `process.platform`, `os.platform()`, `os.type()` and `os.release()` report Windows |
| Hook detection via `toString()` | Instrumented functions report `[native code]`, including through the reflective `Function.prototype.toString.call()` path |
| Delayed execution / logic bombs | The virtual clock is advanced to each scheduled deadline (Layer 5) |
| Absence of data worth stealing | A decoy victim profile supplies bait credentials |
| Event-driven activation | Twenty-seven lifecycle events are fired |
| Input-gated payloads | Command replay seeded with keywords harvested from the specimen |

### Layer 3 — `data-intel.js` (Taint tracking)

Classifies file reads against eighteen secret categories and tracks whether the
bytes read subsequently leave the process. Two claims are distinguished:

| Claim | Definition | Consequence |
|---|---|---|
| **CONFIRMED** | A taint *source* (an observed read) and a taint *sink* (an observed transmission) are joined by matching bytes | The only condition raising a `MALICIOUS` exfiltration verdict |
| **SUSPECTED** | The payload matches a secret pattern, but no corresponding read was observed | Recorded and scored low; never decisive |

Taint sinks comprise HTTP, HTTPS, `fetch`, raw TCP sockets, DNS queries, **and
process command lines** — the latter covering payloads that pass a stolen secret
through a command argument or an environment variable.

Token strength is also tracked. For categories that legitimate tooling routinely
transmits, such as source code, a line-level match cannot confirm theft; a strong
fingerprint is required.

### Layer 4 — `mock-vscode.js` (API simulation)

Implements twelve API namespaces (`window`, `workspace`, `commands`, `languages`,
`extensions`, `env`, `debug`, `scm`, `tasks`, `authentication`, `notebooks`, `lm`)
and maintains a registry of twenty-seven fireable lifecycle events.

Values returned by the simulation are deliberate decoys rather than empty
placeholders. An extension querying `env.machineId`, reading the clipboard, or
requesting an authentication session receives plausible traceable values, because
a payload that receives `undefined` frequently terminates before exhibiting the
behaviour under examination.

### Layer 5 — `time-machine.js` (Virtual clock)

Virtualises `setTimeout`, `setInterval`, `clearTimeout`, `clearInterval`, `Date`
and `performance` within the sandbox context. The scheduler advances the virtual
clock directly to each pending deadline, draining the timer queue up to a horizon
of **366 days**.

The engine yields to the real event loop between firings, so the Node.js main
thread is never blocked. A payload delayed by thirty days resolves within
milliseconds of real time.

### Support modules

* **`decoy-profile.js`** materialises a disposable Windows-shaped user profile
  containing twenty marked decoy secrets (SSH private key, AWS credentials,
  `.npmrc` token, `.env` API keys, browser credential stores, cryptocurrency
  wallets, editor session tokens). `os.homedir()` and twenty Windows environment
  variables are redirected to it. Every value is structurally invalid and
  authenticates against no service. The profile is removed after each run.
* **`native-spoof.js`** maintains a registry of instrumented functions and patches
  `Function.prototype.toString` so both direct and reflective inspection report
  native code.
* **`zip-util.js`** reads the ZIP central directory and inflates entries using
  Node's built-in `zlib`. Path traversal is neutralised and archive-bomb limits
  are enforced.

## A.4 Verdict determination

The combined verdict is the stronger of the static and dynamic verdicts, subject
to one escalation rule.

**Cross-modality corroboration.** The static and dynamic layers constitute
independent observations: one reads the code, the other observes its execution.
Where both identify the same indicator family — for example, a command-and-control
host both present in the source and actually contacted at runtime — two
sub-threshold `SUSPICIOUS` findings are escalated to `MALICIOUS`.

This rule is deliberately narrow. A general rule escalating any two concurrent
`SUSPICIOUS` verdicts was evaluated against the benign control set and produced a
false positive; the family-matched rule produced none.

## A.5 Threat coverage

| Category | Detected behaviours |
|---|---|
| Execution | Download-and-execute cradles; LOLBIN abuse (`powershell -enc`, `certutil -decode`); droppers writing to temporary directories |
| Command and control | Discord and Slack webhooks; Telegram bot API; Solana RPC; Google Calendar, Sheets and Apps Script dead-drops; tunnelling services; hard-coded public IP addresses; anonymous file-drop hosts; darknet endpoints |
| Credential access | Closed-loop exfiltration of SSH keys, cloud credentials, tokens, browser stores and cryptocurrency wallets |
| Discovery | Reconnaissance command batteries combining account and privilege enumeration |
| Persistence | Registry Run keys, scheduled tasks, startup folders, cron entries, launch agents |
| Defence evasion | Windows Defender exclusions; AMSI bypass; invisible-Unicode encoding; obfuscator string arrays; runtime decryption with hard-coded keys |
| Impact | Cryptocurrency mining pool references; clipboard address substitution |
| Supply chain | Obfuscated dependencies within `node_modules` invoking process execution |

## A.6 Evidence tiering — rationale

The VsMex corpus consists of extensions **removed by Microsoft**, and the
`msft_classification_type` field records the *reason for removal* rather than an
assertion that the package contains hostile code. Approximately 47 per cent of
the corpus was removed for brand impersonation, spam, or copyright infringement.
Such packages are frequently exact clones of the legitimate extension and contain
nothing for a code-analysis engine to detect.

The measured detection rate confirms the distinction is material:

| Tier | Samples | STRICT | TRIAGE |
|---|---:|---:|---:|
| code | 1,251 | 30.3% | 54.3% |
| suspect | 762 | 28.0% | 55.9% |
| policy | 1,774 | 15.3% | 28.5% |

Pooling these populations into a single confusion matrix would attribute an
out-of-scope limitation to the detector. The evaluation therefore reports a
code-level matrix as the primary result and a full-corpus matrix as a pessimistic
bound.

Optional filters (`--tiers`, `--exclude-tiers`) permit a run to target one tier.
Their use is documented as a means of answering a scoped question rather than of
improving a headline figure, because 272 samples in the `policy` tier were
independently scored `MALICIOUS` on code evidence; excluding the tier would
discard those detections.

## A.7 Dependencies and file inventory

The engine requires Node.js version 18 or later and has exactly one external
dependency, `acorn`, which is bundled with this package. All other functionality
uses Node.js built-in modules, including ZIP extraction.

```
VSGuard AI/
├── README.md                      Package index and quick start
├── VEXGuard.js                    Orchestrator and CLI          (48.8 KB)
├── benchmark.js                   Evaluation driver             (28.1 KB)
├── dataset.js                     Layer 0 — ingestion           (21.4 KB)
├── preprocess.js                  Layer 1 — static analysis     (53.2 KB)
├── sandbox.js                     Layer 2 — dynamic detonation (143.6 KB)
├── data-intel.js                  Layer 3 — taint tracking      (20.2 KB)
├── mock-vscode.js                 Layer 4 — VS Code API mock    (43.4 KB)
├── time-machine.js                Layer 5 — virtual clock       (19.7 KB)
├── decoy-profile.js               Decoy victim profile           (8.5 KB)
├── native-spoof.js                Anti-analysis cloaking         (4.6 KB)
├── zip-util.js                    ZIP/VSIX reader                (9.7 KB)
├── package.json                   Manifest and npm scripts
├── Run-VEXGuard.ps1               PowerShell launcher
├── VEXGuard_run.bat               Batch launcher
├── node_modules/acorn/            Bundled AST parser
├── docs/                          Documentation (this folder)
└── results/                       Measured evaluation output
```

Source code and inline comments are written in English throughout.

---

# PHẦN B — TIẾNG VIỆT

## B.1 Mục đích

VSGuard AI là engine phân tích lai tĩnh–động, có nhiệm vụ xác định một gói tiện ích
mở rộng Visual Studio Code (`.vsix`) có phải mã độc hay không. Hệ thống nhận đầu
vào là tệp `.vsix` đã đóng gói hoặc thư mục tiện ích đã giải nén, và trả về kết
luận có giải thích kèm báo cáo pháp chứng ánh xạ theo khung MITRE ATT&CK.

Hệ thống được thiết kế với hai điểm vận hành riêng biệt. Quy tắc **STRICT** chỉ coi
kết luận `MALICIOUS` là dương tính, phục vụ mục đích chặn tự động. Quy tắc
**TRIAGE** coi cả `MALICIOUS` lẫn `SUSPICIOUS` là dương tính, phục vụ hàng đợi rà
soát của chuyên viên phân tích. Cả hai luôn được báo cáo song song, bởi việc chỉ
công bố một trong hai sẽ phản ánh sai đặc tính vận hành của hệ thống.

## B.2 Kiến trúc phân tầng

Engine được tổ chức thành sáu tầng phân tích cùng ba mô-đun hỗ trợ.

| Tầng | Mô-đun | Chức năng |
|:---:|---|---|
| 0 | `dataset.js` | Nạp corpus, xác định nhãn chuẩn, phân tầng bằng chứng |
| 1 | `preprocess.js` | Phân tích tĩnh: dựng AST, giải nhiễu, đối sánh IOC |
| 2 | `sandbox.js` | Kích nổ động trong máy ảo có giám sát |
| 3 | `data-intel.js` | Phân loại dữ liệu nhạy cảm và theo vết vòng kín |
| 4 | `mock-vscode.js` | Mô phỏng API tiện ích của Visual Studio Code |
| 5 | `time-machine.js` | Đồng hồ ảo cho phép tua nhanh vượt né tránh theo thời gian |
| — | `decoy-profile.js` | Hồ sơ nạn nhân giả cung cấp thông tin mồi nhử |
| — | `native-spoof.js` | Nguỵ trang chống phân tích cho các hàm đã giám sát |
| — | `zip-util.js` | Bộ đọc container ZIP/VSIX không phụ thuộc thư viện ngoài |

Việc điều phối và đánh giá do hai mô-đun bổ sung đảm nhiệm:

| Mô-đun | Chức năng |
|---|---|
| `VEXGuard.js` | Bộ điều phối, bộ kết luận, trình chạy hàng loạt, giao diện dòng lệnh |
| `benchmark.js` | Trình đánh giá sinh ma trận nhầm lẫn và báo cáo nguyên nhân gốc |

## B.3 Đặc tả các mô-đun

### Tầng 0 — `dataset.js` (Nạp dữ liệu)

Tự động nhận diện hai cấu trúc corpus và xác định nhãn chuẩn cho từng mẫu.

* **Cấu trúc DataDog** — `<publisher>.<name>/<version>.vsix`, có thể kèm cây thư
  mục `<version>/extension/` đã giải nén sẵn. Nhãn suy ra từ cây thư mục chứa mẫu.
* **Cấu trúc VsMex** — `extensions/<publisher>.<name>/<version>/<file>.vsix`, nhãn
  lấy từ hai tệp metadata theo chính lý do gỡ bỏ của Microsoft.

Ba nguyên tắc bất biến khi nạp dữ liệu:

1. Thư mục `node_modules` **không bao giờ** được duyệt khi **phát hiện mẫu**. Một
   tiện ích có thể đóng gói hàng nghìn tệp `package.json` lồng nhau; coi mỗi tệp
   là một mẫu riêng sẽ thổi phồng corpus và lặp lại công việc. Tầng phân tích tĩnh
   vẫn *đọc* bên trong `node_modules`, vì trojan chuỗi cung ứng ẩn ở đó — quy tắc
   loại trừ chi phối *cái gì được tính là một mẫu*, không phải *cái gì được quét*.
2. Khi một mẫu tồn tại đồng thời dưới dạng `.vsix` và thư mục đã giải nén, bản
   `.vsix` được ưu tiên. Cây đã giải nén có thể còn sót `execution-log.json` và
   `static-analysis.json` từ các lần chạy trước.
3. Mỗi mẫu được gán một **tầng bằng chứng** suy từ phân loại — `code`, `suspect`,
   `policy` hoặc `unknown`. Mục B.6 giải thích vì sao trường này là bắt buộc.

### Tầng 1 — `preprocess.js` (Phân tích tĩnh)

Dựng cây cú pháp trừu tượng cho từng tệp JavaScript bằng `acorn`, và đánh giá
*hình dạng* của cấu trúc lệnh thay vì sự hiện diện của từ khoá.

| Cấu trúc | Cơ sở đánh giá |
|---|---|
| `eval()` / `new Function()` | Bản chất của đối số. Chuỗi tĩnh và dạng JSON bọc ngoặc được bỏ qua; chỉ việc thực thi dữ liệu đã giải mã mới mang tính quyết định. |
| `child_process.*` | Đối số lệnh có tĩnh hay không. Lệnh tĩnh là công cụ thông thường; lệnh đã giải mã là bộ nạp mã. |
| Ghi tệp | Đích ghi. Ghi vào thư mục tạm, vùng lưu trữ tiện ích hoặc `.vscode` được bỏ qua; ghi tệp thực thi hoặc vào vị trí khởi động cùng hệ thống bị đánh dấu. |
| Cradle tải-và-chạy | Yêu cầu đồng thời trình thông dịch, tham chiếu payload từ xa, và động từ thực thi **trong cùng một chuỗi ký tự**. |

Các chỉ dấu được tách thành hai tầng:

* Chỉ dấu **PRIMARY** khẳng định ý đồ độc hại một cách độc lập. Kết luận tĩnh
  `MALICIOUS` đòi hỏi điểm primary tối thiểu là 45.
* Chỉ dấu **SUPPORTING** thể hiện *khả năng* chứ không phải *ý đồ*. Tổng đóng góp
  của chúng bị giới hạn ở 35 điểm, nên việc tích luỹ nhiều khả năng không bao giờ
  tự đạt tới kết luận `MALICIOUS`.

Mô-đun hiện chứa 17 nhóm chỉ dấu xâm nhập, ba danh sách lệnh trinh sát phân theo
mức độ ý đồ, và một tập quy tắc dựa trên hình dạng lời gọi trong AST.

### Tầng 2 — `sandbox.js` (Kích nổ động)

Thực thi tiện ích bên trong `vm.createContext()` với mười một mô-đun được giám
sát: `vscode`, `child_process`, `http`, `https`, `fs`, `fs/promises`, `os`, `net`,
`dns`, `crypto` và `axios`.

Đặc tính cách ly:

* Thao tác ghi tệp bị chặn và huỷ bỏ.
* Lời gọi mạng được trả lời bằng mô phỏng; không có lưu lượng nào rời khỏi máy.
* Không tiến trình hệ điều hành nào được tạo ra.
* Việc thực thi diễn ra trong tiến trình con, bổ sung lớp cách ly cấp hệ điều hành
  bên cạnh ranh giới máy ảo.

Biện pháp đối phó né tránh:

| Kỹ thuật né tránh | Biện pháp đối phó |
|---|---|
| Chặn theo hệ điều hành | `process.platform`, `os.platform()`, `os.type()` và `os.release()` đều báo Windows |
| Dò hook qua `toString()` | Hàm được giám sát báo `[native code]`, kể cả qua đường phản chiếu `Function.prototype.toString.call()` |
| Trì hoãn thực thi / bom hẹn giờ | Đồng hồ ảo được tua tới từng mốc đã lên lịch (Tầng 5) |
| Không có dữ liệu đáng đánh cắp | Hồ sơ nạn nhân giả cung cấp thông tin mồi nhử |
| Kích hoạt theo sự kiện | Hai mươi bảy sự kiện vòng đời được phát ra |
| Payload chặn theo dữ liệu nhập | Chạy lại lệnh với từ khoá thu thập từ chính mã nguồn mẫu |

### Tầng 3 — `data-intel.js` (Theo vết dữ liệu)

Phân loại các thao tác đọc tệp theo mười tám nhóm bí mật và theo dõi xem những
byte đã đọc có rời khỏi tiến trình hay không. Hai loại khẳng định được phân biệt:

| Khẳng định | Định nghĩa | Hệ quả |
|---|---|---|
| **CONFIRMED** | Một *nguồn* nhiễm (thao tác đọc quan sát được) và một *đích* nhiễm (thao tác gửi quan sát được) khớp nhau về nội dung byte | Điều kiện duy nhất dẫn tới kết luận rò rỉ `MALICIOUS` |
| **SUSPECTED** | Payload khớp mẫu bí mật, nhưng không quan sát được thao tác đọc tương ứng | Được ghi nhận, chấm điểm thấp, không bao giờ mang tính quyết định |

Đích nhiễm bao gồm HTTP, HTTPS, `fetch`, socket TCP thô, truy vấn DNS, **và dòng
lệnh tiến trình** — trường hợp cuối bao phủ các payload chuyển bí mật qua tham số
lệnh hoặc biến môi trường.

Độ mạnh của dấu vết cũng được theo dõi. Với những nhóm mà công cụ hợp pháp thường
xuyên truyền đi, chẳng hạn mã nguồn, việc khớp ở mức dòng không đủ để khẳng định
hành vi đánh cắp; cần một dấu vết mạnh.

### Tầng 4 — `mock-vscode.js` (Mô phỏng API)

Hiện thực mười hai không gian tên API (`window`, `workspace`, `commands`,
`languages`, `extensions`, `env`, `debug`, `scm`, `tasks`, `authentication`,
`notebooks`, `lm`) và duy trì sổ đăng ký gồm hai mươi bảy sự kiện vòng đời có thể
kích hoạt.

Các giá trị do mô phỏng trả về là **mồi nhử có chủ đích**, không phải giá trị rỗng.
Tiện ích truy vấn `env.machineId`, đọc clipboard hoặc yêu cầu phiên xác thực sẽ
nhận được giá trị hợp lý và có thể truy vết, bởi payload nhận về `undefined`
thường kết thúc sớm trước khi bộc lộ hành vi cần khảo sát.

### Tầng 5 — `time-machine.js` (Đồng hồ ảo)

Ảo hoá `setTimeout`, `setInterval`, `clearTimeout`, `clearInterval`, `Date` và
`performance` bên trong ngữ cảnh sandbox. Bộ lập lịch tua đồng hồ ảo thẳng tới
từng mốc đang chờ, rút cạn hàng đợi bộ đếm thời gian trong phạm vi **366 ngày**.

Engine nhường quyền điều khiển cho vòng lặp sự kiện thật giữa các lần kích hoạt,
do đó luồng chính Node.js không bao giờ bị chặn. Một payload trì hoãn ba mươi ngày
được giải quyết trong vài mili-giây thời gian thực.

### Các mô-đun hỗ trợ

* **`decoy-profile.js`** tạo một hồ sơ người dùng dạng Windows dùng một lần, chứa
  hai mươi bí mật mồi nhử được đánh dấu (khoá riêng SSH, thông tin đăng nhập AWS,
  token `.npmrc`, khoá API trong `.env`, kho thông tin đăng nhập trình duyệt, ví
  tiền mã hoá, token phiên của trình soạn thảo). `os.homedir()` cùng hai mươi biến
  môi trường Windows được trỏ về hồ sơ này. Mọi giá trị đều không hợp lệ về cấu
  trúc và không xác thực được với bất kỳ dịch vụ nào. Hồ sơ bị xoá sau mỗi lần chạy.
* **`native-spoof.js`** duy trì sổ đăng ký các hàm đã giám sát và vá
  `Function.prototype.toString` để cả kiểm tra trực tiếp lẫn phản chiếu đều báo
  về mã gốc (native).
* **`zip-util.js`** đọc thư mục trung tâm của ZIP và giải nén bằng `zlib` có sẵn
  trong Node. Kỹ thuật vượt đường dẫn bị vô hiệu hoá và giới hạn chống bom nén
  được áp dụng.

## B.4 Xác định kết luận

Kết luận tổng hợp là giá trị mạnh hơn giữa kết luận tĩnh và kết luận động, kèm
theo một quy tắc nâng cấp.

**Đối chứng chéo giữa hai phương thức.** Tầng tĩnh và tầng động là hai quan sát
độc lập: một bên đọc mã, một bên quan sát mã chạy. Khi cả hai cùng chỉ ra một nhóm
chỉ dấu — ví dụ một máy chủ điều khiển vừa xuất hiện trong mã nguồn vừa thực sự
được liên lạc lúc chạy — hai phát hiện `SUSPICIOUS` dưới ngưỡng được nâng thành
`MALICIOUS`.

Quy tắc này được thiết kế hẹp một cách có chủ đích. Một quy tắc tổng quát nâng cấp
bất kỳ hai kết luận `SUSPICIOUS` đồng thời nào đã được đánh giá trên tập đối chứng
lành tính và tạo ra một dương tính giả; quy tắc khớp theo nhóm chỉ dấu không tạo
ra dương tính giả nào.

## B.5 Phạm vi mối đe doạ được phát hiện

| Nhóm | Hành vi được phát hiện |
|---|---|
| Thực thi | Cradle tải-và-chạy; lạm dụng LOLBIN (`powershell -enc`, `certutil -decode`); dropper ghi vào thư mục tạm |
| Điều khiển từ xa | Webhook Discord và Slack; API bot Telegram; Solana RPC; dead-drop qua Google Calendar, Sheets, Apps Script; dịch vụ đường hầm; địa chỉ IP công cộng cứng; máy chủ lưu trữ tệp ẩn danh; điểm cuối darknet |
| Truy cập thông tin xác thực | Rò rỉ vòng kín khoá SSH, thông tin đám mây, token, kho trình duyệt và ví tiền mã hoá |
| Trinh sát | Chuỗi lệnh trinh sát kết hợp liệt kê tài khoản và đặc quyền |
| Duy trì hiện diện | Khoá Run trong registry, tác vụ hẹn giờ, thư mục khởi động, cron, launch agent |
| Né tránh phòng thủ | Loại trừ Windows Defender; vượt AMSI; mã hoá Unicode vô hình; mảng chuỗi của trình làm rối mã; giải mã lúc chạy bằng khoá cứng |
| Tác động | Tham chiếu tới pool đào tiền mã hoá; thay thế địa chỉ trong clipboard |
| Chuỗi cung ứng | Phụ thuộc bị làm rối trong `node_modules` gọi thực thi tiến trình |

## B.6 Phân tầng bằng chứng — cơ sở lý luận

Corpus VsMex bao gồm các tiện ích **bị Microsoft gỡ bỏ**, và trường
`msft_classification_type` ghi nhận *lý do gỡ bỏ* chứ không khẳng định rằng gói
tiện ích chứa mã độc. Khoảng 47 phần trăm corpus bị gỡ vì mạo danh thương hiệu,
spam hoặc vi phạm bản quyền. Những gói này thường là bản sao chính xác của tiện
ích hợp pháp và không chứa gì để một engine phân tích mã có thể phát hiện.

Tỷ lệ phát hiện đo được xác nhận sự phân biệt này là có ý nghĩa:

| Tầng | Số mẫu | STRICT | TRIAGE |
|---|---:|---:|---:|
| code | 1.251 | 30,3% | 54,3% |
| suspect | 762 | 28,0% | 55,9% |
| policy | 1.774 | 15,3% | 28,5% |

Gộp các quần thể này vào một ma trận nhầm lẫn duy nhất sẽ quy một giới hạn nằm
ngoài phạm vi thiết kế thành lỗi của bộ dò. Do đó phần đánh giá báo cáo ma trận
tầng code làm kết quả chính và ma trận toàn corpus làm cận dưới bi quan.

Các bộ lọc tuỳ chọn (`--tiers`, `--exclude-tiers`) cho phép một lần chạy nhắm vào
một tầng cụ thể. Tài liệu quy định rõ chúng là công cụ trả lời một câu hỏi có phạm
vi xác định, không phải công cụ cải thiện con số công bố, bởi 272 mẫu thuộc tầng
`policy` đã được chấm `MALICIOUS` một cách độc lập dựa trên bằng chứng mã; loại bỏ
tầng này đồng nghĩa với việc vứt bỏ những phát hiện đó.

## B.7 Phụ thuộc và danh mục tệp

Engine yêu cầu Node.js phiên bản 18 trở lên và có đúng một phụ thuộc bên ngoài là
`acorn`, đã được đóng gói kèm. Mọi chức năng còn lại sử dụng mô-đun tích hợp sẵn
của Node.js, bao gồm cả việc giải nén ZIP.

```
VSGuard AI/
├── README.md                      Mục lục gói và hướng dẫn bắt đầu nhanh
├── VEXGuard.js                    Bộ điều phối và CLI            (48,8 KB)
├── benchmark.js                   Trình đánh giá                 (28,1 KB)
├── dataset.js                     Tầng 0 — nạp dữ liệu           (21,4 KB)
├── preprocess.js                  Tầng 1 — phân tích tĩnh        (53,2 KB)
├── sandbox.js                     Tầng 2 — kích nổ động         (143,6 KB)
├── data-intel.js                  Tầng 3 — theo vết dữ liệu      (20,2 KB)
├── mock-vscode.js                 Tầng 4 — mô phỏng API VS Code  (43,4 KB)
├── time-machine.js                Tầng 5 — đồng hồ ảo            (19,7 KB)
├── decoy-profile.js               Hồ sơ nạn nhân giả              (8,5 KB)
├── native-spoof.js                Nguỵ trang chống phân tích      (4,6 KB)
├── zip-util.js                    Bộ đọc ZIP/VSIX                 (9,7 KB)
├── package.json                   Tệp kê khai và script npm
├── Run-VEXGuard.ps1               Trình khởi chạy PowerShell
├── VEXGuard_run.bat               Trình khởi chạy Batch
├── node_modules/acorn/            Bộ phân tích AST đóng gói kèm
├── docs/                          Tài liệu (thư mục này)
└── results/                       Kết quả đánh giá đã đo
```

Mã nguồn và chú thích trong mã được viết hoàn toàn bằng tiếng Anh.
