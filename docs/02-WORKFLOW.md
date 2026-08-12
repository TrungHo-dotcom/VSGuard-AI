# 02 — System Workflow / Quy trình vận hành hệ thống

**System:** VSGuard AI (engine identifier: VEXGuard v3.1)
**Subject:** CSN 304 — *Towards Identifying Malicious VS Code Extensions*
**Document date:** 2026-08-06

---

# PART A — ENGLISH

## A.1 Overview of the pipeline

Analysis of a single sample proceeds through eight sequential stages. Stages 2 and
3 are independent of one another and constitute the two analytical modalities whose
results are later combined.

```
   ┌──────────────────────────────────────────────────────────────┐
   │  STAGE 1   INGESTION            dataset.js                   │
   │            Locate samples, resolve ground truth, assign tier │
   └───────────────────────────┬──────────────────────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  STAGE 2   UNPACKING            zip-util.js                  │
   │            Read ZIP container, descend to extension root     │
   └───────────────────────────┬──────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
   ┌──────────▼───────────┐        ┌────────────▼─────────────────┐
   │ STAGE 3  STATIC      │        │ STAGE 4  DYNAMIC             │
   │          preprocess  │        │          sandbox.js          │
   │  · AST parse         │        │  · Decoy profile             │
   │  · De-obfuscate      │        │  · Install hooks + cloaking  │
   │  · IOC match         │        │  · Execute + activate()      │
   │  · Two-tier score    │        │  · Fire 27 events            │
   │                      │        │  · Replay commands           │
   │                      │        │  · Fast-forward 366 days     │
   └──────────┬───────────┘        └────────────┬─────────────────┘
              │                                 │
              │                    ┌────────────▼─────────────────┐
              │                    │ STAGE 5  TAINT               │
              │                    │          data-intel.js       │
              │                    │  Source → Sink correlation   │
              │                    └────────────┬─────────────────┘
              │                                 │
              └────────────────┬────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  STAGE 6   VERDICT              VEXGuard.js                  │
   │            max(static, dynamic) + corroboration escalation   │
   └───────────────────────────┬──────────────────────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  STAGE 7   FORENSIC REPORT      VEXGuard.js                  │
   │            MITRE ATT&CK narrative, IOCs, proven data flows   │
   └───────────────────────────┬──────────────────────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  STAGE 8   EVALUATION           benchmark.js                 │
   │            Confusion matrices, root-cause attribution        │
   └──────────────────────────────────────────────────────────────┘
```

## A.2 Stage 1 — Ingestion

**Input:** a corpus root directory.
**Output:** an ordered list of sample descriptors.

The module identifies the corpus layout, enumerates candidate samples, and attaches
to each a ground-truth label and an evidence tier. Directories named `node_modules`
are excluded from enumeration. Where both a `.vsix` archive and a pre-extracted
directory exist for the same sample, the archive is retained and the directory
discarded.

Each descriptor carries: identifier, publisher, name, version, absolute path,
label, classification, and evidence tier.

## A.3 Stage 2 — Unpacking

**Input:** a `.vsix` path.
**Output:** a filesystem path to the extension root.

The ZIP central directory is parsed and entries are inflated using Node's built-in
`zlib`. Entry names are sanitised against path traversal before any write occurs,
and archive-bomb limits bound both entry count and total extracted volume. The
module then descends to the directory containing `package.json`.

Extraction targets a scratch directory, which is deleted once analysis of the
sample concludes.

## A.4 Stage 3 — Static analysis

**Input:** the extension root.
**Output:** a static verdict with scored, attributed reasons.

The module walks the extension tree and processes each text file as follows:

1. **De-obfuscation.** Hexadecimal and Unicode escape sequences are decoded, and
   embedded Base64 blobs are decoded where the result is printable.
2. **AST construction.** JavaScript files are parsed with `acorn`. Where parsing
   fails — commonly a sign of deliberate mangling — the module degrades to a
   tightened regular-expression path rather than abandoning the file.
3. **Indicator matching.** High-confidence host indicators are matched everywhere,
   including inside `node_modules`, since supply-chain trojans reside there.
   Generic behavioural markers are matched only in the extension's own code.
4. **Call-shape analysis.** Constructs are judged by argument shape as described in
   document 01, section A.3.
5. **Scoring.** Findings are separated into PRIMARY and SUPPORTING tiers. The
   supporting total is capped, and a `MALICIOUS` verdict requires primary evidence.

Output is written to `static-analysis.json` alongside the sample.

## A.5 Stage 4 — Dynamic detonation

**Input:** the extension root.
**Output:** an execution log with a behavioural verdict.

The sequence is as follows.

**4.1 Environment preparation.** A disposable decoy victim profile is created and
populated with twenty marked bait secrets. `os.homedir()` and twenty Windows
environment variables are redirected to it.

**4.2 Hook installation.** Eleven modules are replaced with instrumented versions.
Every instrumented function is registered with the cloaking layer, and
`Function.prototype.toString` is patched so that both direct and reflective
inspection report native code. `process.platform` and `process.arch` are set to
report Windows on x64.

**4.3 Virtual clock installation.** Timer functions, `Date` and `performance` are
replaced with virtualised equivalents within the sandbox context.

**4.4 Module loading.** The entry point is read. Where the source uses ECMAScript
module syntax, it is transpiled to CommonJS so that execution can proceed. The code
is compiled and executed inside `vm.createContext()` under a ten-second synchronous
limit.

**4.5 Activation.** The extension context is constructed with twelve credential
keys and eight state flags pre-populated, so that code paths gated on licensing or
first-run state are reachable. `activate()` is then invoked.

Where `activate()` returns a promise that does not settle, the harness does not
block indefinitely. It settles briefly, then advances the virtual clock to release
any awaited delay, then allows the continuation a bounded window. This is necessary
because a payload of the form `await sleep(30 days)` resolves only on a virtual
timer, which fires only when the clock is advanced — a promise the harness would
otherwise be waiting on while itself preventing its resolution.

**4.6 Event simulation.** Twenty-seven lifecycle events are fired in the order a
genuine editing session would produce them, each with a correctly shaped payload.

**4.7 Command replay.** Every registered command is invoked. The sequence is then
repeated with keywords harvested from the specimen's own source injected into the
mocked input box and quick-pick controls, so that payloads gated on typed input are
reached.

**4.8 Document-content fuzzing.** Where the extension has registered a document
listener, the mocked document body is rewritten with each candidate keyword and the
document lifecycle re-fired, so that payloads gated on file content are reached.
This stage is skipped when no listener is registered, since firing events at an
extension that is not listening consumes the time budget without benefit.

**4.9 Virtual clock fast-forward.** The scheduler advances to each pending deadline
in turn, up to a 366-day horizon. A second pass follows the first, because firing a
timer frequently schedules further work — a callback awaiting a mocked network
response whose continuation schedules the next beacon.

**4.10 Report generation.** The execution log is written to `execution-log.json`,
the decoy profile is removed, environment variables are restored, and the process
exits deliberately rather than waiting for the event loop to drain.

## A.6 Stage 5 — Taint correlation

Taint tracking operates throughout stage 4 rather than as a discrete phase.

**Source registration.** Every file read is classified against eighteen secret
categories by path and by content. Where a match occurs, distinctive fingerprints
of the bytes read are registered.

**Sink inspection.** Every outbound transmission — HTTP, HTTPS, `fetch`, raw TCP,
DNS, and process command lines including argument vectors and environment overrides
— is decoded through Base64, URL and hexadecimal layers and compared against the
registered fingerprints.

**Adjudication.** A `CONFIRMED` finding requires matching bytes across the two
observations, and for categories that legitimate tooling routinely transmits it
additionally requires a strong fingerprint rather than a line-level match. A
pattern match without a corresponding observed read yields `SUSPECTED`, which is
recorded but never decisive.

Values injected by the harness itself are registered and excluded, so an extension
echoing back a token supplied by the simulation is not counted as exfiltration.

## A.7 Stage 6 — Verdict combination

The combined verdict is the stronger of the two modal verdicts. Where both
modalities are `SUSPICIOUS` and both identify the same indicator family, the
verdict is escalated to `MALICIOUS` on the basis that two independent observations
corroborate one another.

Two decision rules are derived from the verdict:

| Rule | Positive class | Intended use |
|---|---|---|
| STRICT | `MALICIOUS` only | Automated blocking or removal |
| TRIAGE | `MALICIOUS` or `SUSPICIOUS` | Analyst review queue |

## A.8 Stage 7 — Forensic reporting

Behaviours observed are mapped to MITRE ATT&CK techniques and rendered as a
narrative accompanied by indicators of compromise, contacted hosts, attempted
commands, and — where exfiltration was confirmed — the complete source-to-sink data
flow naming the file read and the destination.

## A.9 Stage 8 — Batch evaluation

For corpus-scale evaluation, `benchmark.js` drives the pipeline across both corpora
using a bounded worker pool. Results stream to CSV and JSONL as each sample
completes, so an interrupted run may be resumed. Confusion matrices are computed
under both decision rules and stratified by evidence tier and by removal reason.
Every false positive and false negative is attributed to one of eight named causes.

## A.10 Operational procedure

**Verification of installation.** The following constructs a synthetic
operating-system-gated, ninety-day time-bombed credential stealer, detonates it,
and asserts that the beacon and the proven data flow were both captured:

```
node VEXGuard.js --selftest
```

**Analysis of a single extension:**

```
node VEXGuard.js <path-to-extension.vsix>
```

**Full corpus evaluation:**

```
node benchmark.js --datasets all --concurrency 8 --timeout 120000
```

**Principal options:**

| Option | Effect |
|---|---|
| `--datasets all\|datadog\|vsmex` | Selects the corpora to analyse |
| `--concurrency N` | Number of samples analysed in parallel |
| `--timeout MS` | Per-sample detonation limit |
| `--limit N` | Caps samples per corpus, for a short verification run |
| `--latest-only` | Retains only the newest version of each extension |
| `--tiers` / `--exclude-tiers` | Restricts analysis to selected evidence tiers |
| `--resume` | Skips samples already present in the results file |
| `--report-only` | Regenerates reports from existing results without re-analysis |

---

# PHẦN B — TIẾNG VIỆT

## B.1 Tổng quan quy trình

Việc phân tích một mẫu diễn ra qua tám giai đoạn tuần tự. Giai đoạn 3 và 4 độc lập
với nhau và tạo thành hai phương thức phân tích mà kết quả sẽ được tổng hợp về sau.

```
   ┌──────────────────────────────────────────────────────────────┐
   │  GĐ 1   NẠP DỮ LIỆU             dataset.js                   │
   │         Định vị mẫu, xác định nhãn chuẩn, gán tầng bằng chứng│
   └───────────────────────────┬──────────────────────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  GĐ 2   GIẢI NÉN                zip-util.js                  │
   │         Đọc container ZIP, đi xuống thư mục gốc tiện ích     │
   └───────────────────────────┬──────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
   ┌──────────▼───────────┐        ┌────────────▼─────────────────┐
   │ GĐ 3  PHÂN TÍCH TĨNH │        │ GĐ 4  PHÂN TÍCH ĐỘNG         │
   │       preprocess.js  │        │       sandbox.js             │
   │  · Dựng AST          │        │  · Hồ sơ mồi nhử             │
   │  · Giải nhiễu        │        │  · Cài hook + nguỵ trang     │
   │  · Đối sánh IOC      │        │  · Thực thi + activate()     │
   │  · Chấm điểm 2 tầng  │        │  · Bắn 27 sự kiện            │
   │                      │        │  · Chạy lại lệnh             │
   │                      │        │  · Tua nhanh 366 ngày        │
   └──────────┬───────────┘        └────────────┬─────────────────┘
              │                                 │
              │                    ┌────────────▼─────────────────┐
              │                    │ GĐ 5  THEO VẾT DỮ LIỆU       │
              │                    │       data-intel.js          │
              │                    │  Đối chiếu Nguồn → Đích      │
              │                    └────────────┬─────────────────┘
              │                                 │
              └────────────────┬────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  GĐ 6   KẾT LUẬN                VEXGuard.js                  │
   │         max(tĩnh, động) + nâng cấp theo đối chứng chéo       │
   └───────────────────────────┬──────────────────────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  GĐ 7   BÁO CÁO PHÁP CHỨNG      VEXGuard.js                  │
   │         Diễn giải MITRE ATT&CK, IOC, luồng dữ liệu đã chứng  │
   └───────────────────────────┬──────────────────────────────────┘
                               │
   ┌───────────────────────────▼──────────────────────────────────┐
   │  GĐ 8   ĐÁNH GIÁ                benchmark.js                 │
   │         Ma trận nhầm lẫn, quy trách nhiệm nguyên nhân gốc    │
   └──────────────────────────────────────────────────────────────┘
```

## B.2 Giai đoạn 1 — Nạp dữ liệu

**Đầu vào:** thư mục gốc của corpus.
**Đầu ra:** danh sách mô tả mẫu đã sắp xếp.

Mô-đun nhận diện cấu trúc corpus, liệt kê các mẫu ứng viên, và gán cho mỗi mẫu một
nhãn chuẩn cùng một tầng bằng chứng. Thư mục `node_modules` bị loại khỏi quá trình
liệt kê. Khi một mẫu tồn tại đồng thời dưới dạng `.vsix` và thư mục đã giải nén sẵn,
bản `.vsix` được giữ lại và thư mục bị loại bỏ.

Mỗi bản mô tả mang theo: định danh, nhà phát hành, tên, phiên bản, đường dẫn tuyệt
đối, nhãn, phân loại và tầng bằng chứng.

## B.3 Giai đoạn 2 — Giải nén

**Đầu vào:** đường dẫn tệp `.vsix`.
**Đầu ra:** đường dẫn tới thư mục gốc của tiện ích.

Thư mục trung tâm của ZIP được phân tích và các mục được giải nén bằng `zlib` tích
hợp sẵn trong Node. Tên các mục được làm sạch để chống kỹ thuật vượt đường dẫn
trước khi bất kỳ thao tác ghi nào diễn ra, và giới hạn chống bom nén ràng buộc cả
số lượng mục lẫn tổng dung lượng giải nén. Sau đó mô-đun đi xuống thư mục chứa
`package.json`.

Việc giải nén hướng tới một thư mục tạm, thư mục này bị xoá khi phân tích mẫu kết
thúc.

## B.4 Giai đoạn 3 — Phân tích tĩnh

**Đầu vào:** thư mục gốc tiện ích.
**Đầu ra:** kết luận tĩnh kèm các lý do đã chấm điểm và quy nguồn.

Mô-đun duyệt cây thư mục tiện ích và xử lý từng tệp văn bản theo trình tự sau:

1. **Giải nhiễu.** Các chuỗi thoát hệ thập lục phân và Unicode được giải mã, các
   khối Base64 nhúng được giải mã khi kết quả là văn bản đọc được.
2. **Dựng AST.** Tệp JavaScript được phân tích bằng `acorn`. Khi việc phân tích thất
   bại — thường là dấu hiệu của việc cố tình làm rối mã — mô-đun chuyển sang nhánh
   biểu thức chính quy đã siết chặt thay vì bỏ qua tệp.
3. **Đối sánh chỉ dấu.** Chỉ dấu máy chủ có độ tin cậy cao được đối sánh ở mọi nơi,
   kể cả bên trong `node_modules`, vì trojan chuỗi cung ứng ẩn ở đó. Các dấu hiệu
   hành vi chung chỉ được đối sánh trong mã của chính tiện ích.
4. **Phân tích hình dạng lời gọi.** Các cấu trúc được đánh giá theo hình dạng đối số
   như mô tả tại tài liệu 01, mục B.3.
5. **Chấm điểm.** Các phát hiện được tách thành tầng PRIMARY và SUPPORTING. Tổng
   điểm supporting bị giới hạn, và kết luận `MALICIOUS` bắt buộc phải có bằng chứng
   primary.

Kết quả được ghi ra tệp `static-analysis.json` cạnh mẫu phân tích.

## B.5 Giai đoạn 4 — Kích nổ động

**Đầu vào:** thư mục gốc tiện ích.
**Đầu ra:** nhật ký thực thi kèm kết luận hành vi.

Trình tự thực hiện như sau.

**4.1 Chuẩn bị môi trường.** Một hồ sơ nạn nhân giả dùng một lần được tạo ra và nạp
hai mươi bí mật mồi nhử có đánh dấu. `os.homedir()` cùng hai mươi biến môi trường
Windows được trỏ về hồ sơ này.

**4.2 Cài đặt hook.** Mười một mô-đun được thay thế bằng phiên bản có giám sát. Mọi
hàm được giám sát đều đăng ký với tầng nguỵ trang, và `Function.prototype.toString`
được vá để cả kiểm tra trực tiếp lẫn phản chiếu đều báo về mã gốc.
`process.platform` và `process.arch` được đặt để báo Windows trên kiến trúc x64.

**4.3 Cài đặt đồng hồ ảo.** Các hàm hẹn giờ, `Date` và `performance` được thay bằng
phiên bản ảo hoá trong ngữ cảnh sandbox.

**4.4 Nạp mô-đun.** Điểm vào được đọc. Nếu mã nguồn dùng cú pháp ECMAScript module,
mã sẽ được chuyển đổi sang CommonJS để có thể thực thi. Mã được biên dịch và chạy
bên trong `vm.createContext()` dưới giới hạn đồng bộ mười giây.

**4.5 Kích hoạt.** Ngữ cảnh tiện ích được dựng với mười hai khoá thông tin xác thực
và tám cờ trạng thái nạp sẵn, để những nhánh mã bị chặn bởi điều kiện bản quyền
hoặc lần chạy đầu tiên đều có thể tiếp cận. Sau đó `activate()` được gọi.

Khi `activate()` trả về một promise không bao giờ hoàn tất, bộ khung không chờ vô
hạn. Nó chờ ngắn, rồi tua đồng hồ ảo để giải phóng độ trễ đang bị chờ, rồi cấp cho
phần tiếp theo một khoảng thời gian có giới hạn. Bước này là cần thiết vì payload
dạng `await sleep(30 ngày)` chỉ hoàn tất khi bộ đếm ảo kích hoạt, mà bộ đếm ảo chỉ
kích hoạt khi đồng hồ được tua — nghĩa là bộ khung sẽ chờ một promise mà chính nó
đang ngăn không cho hoàn tất.

**4.6 Mô phỏng sự kiện.** Hai mươi bảy sự kiện vòng đời được bắn ra theo thứ tự mà
một phiên soạn thảo thật sẽ tạo ra, mỗi sự kiện kèm dữ liệu đúng định dạng.

**4.7 Chạy lại lệnh.** Mọi lệnh đã đăng ký đều được gọi. Sau đó trình tự được lặp
lại với các từ khoá thu thập từ chính mã nguồn của mẫu, được đưa vào hộp nhập liệu
và bộ chọn nhanh đã mô phỏng, nhằm tiếp cận những payload bị chặn bởi dữ liệu người
dùng gõ vào.

**4.8 Fuzzing nội dung tài liệu.** Nếu tiện ích có đăng ký bộ lắng nghe tài liệu,
nội dung tài liệu mô phỏng được ghi lại theo từng từ khoá ứng viên và vòng đời tài
liệu được bắn lại, nhằm tiếp cận payload bị chặn bởi nội dung tệp. Bước này được bỏ
qua khi không có bộ lắng nghe nào đăng ký, vì bắn sự kiện tới một tiện ích không
lắng nghe chỉ tiêu tốn thời gian mà không mang lại lợi ích.

**4.9 Tua nhanh đồng hồ ảo.** Bộ lập lịch lần lượt tiến tới từng mốc đang chờ, trong
phạm vi 366 ngày. Một lượt thứ hai được thực hiện sau lượt đầu, bởi việc kích hoạt
một bộ đếm thường sinh ra công việc mới — một callback đang chờ phản hồi mạng mô
phỏng, mà phần tiếp theo của nó lại lên lịch cho lần phát tín hiệu kế tiếp.

**4.10 Sinh báo cáo.** Nhật ký thực thi được ghi ra `execution-log.json`, hồ sơ mồi
nhử bị xoá, các biến môi trường được khôi phục, và tiến trình chủ động thoát thay
vì chờ vòng lặp sự kiện cạn.

## B.6 Giai đoạn 5 — Đối chiếu vết nhiễm

Việc theo vết diễn ra xuyên suốt giai đoạn 4 chứ không phải là một pha riêng biệt.

**Đăng ký nguồn.** Mọi thao tác đọc tệp được phân loại theo mười tám nhóm bí mật,
dựa trên cả đường dẫn lẫn nội dung. Khi có khớp, các dấu vết đặc trưng của phần byte
đã đọc sẽ được đăng ký.

**Kiểm tra đích.** Mọi luồng truyền ra ngoài — HTTP, HTTPS, `fetch`, TCP thô, DNS,
và dòng lệnh tiến trình bao gồm cả mảng tham số lẫn biến môi trường ghi đè — đều
được giải mã qua các lớp Base64, URL và thập lục phân, rồi đối chiếu với các dấu vết
đã đăng ký.

**Phán định.** Một phát hiện `CONFIRMED` đòi hỏi phần byte khớp nhau giữa hai quan
sát, và với những nhóm mà công cụ hợp pháp thường xuyên truyền đi, còn đòi hỏi thêm
một dấu vết mạnh thay vì chỉ khớp ở mức dòng. Việc khớp mẫu mà không có thao tác đọc
tương ứng chỉ cho kết quả `SUSPECTED`, được ghi nhận nhưng không mang tính quyết
định.

Những giá trị do chính bộ khung đưa vào đều được đăng ký và loại trừ, nên việc tiện
ích gửi trả lại một token do mô phỏng cung cấp sẽ không bị tính là hành vi rò rỉ.

## B.7 Giai đoạn 6 — Tổng hợp kết luận

Kết luận tổng hợp là giá trị mạnh hơn giữa hai kết luận theo phương thức. Khi cả hai
phương thức đều cho `SUSPICIOUS` và cùng chỉ ra một nhóm chỉ dấu, kết luận được nâng
lên `MALICIOUS` trên cơ sở hai quan sát độc lập đã đối chứng lẫn nhau.

Hai quy tắc quyết định được rút ra từ kết luận:

| Quy tắc | Lớp dương tính | Mục đích sử dụng |
|---|---|---|
| STRICT | Chỉ `MALICIOUS` | Chặn hoặc gỡ bỏ tự động |
| TRIAGE | `MALICIOUS` hoặc `SUSPICIOUS` | Hàng đợi rà soát của chuyên viên |

## B.8 Giai đoạn 7 — Báo cáo pháp chứng

Các hành vi quan sát được ánh xạ sang kỹ thuật MITRE ATT&CK và trình bày dưới dạng
diễn giải, kèm theo chỉ dấu xâm nhập, danh sách máy chủ đã liên lạc, các lệnh đã
thử thực thi, và — trong trường hợp rò rỉ đã được xác nhận — toàn bộ luồng dữ liệu
từ nguồn tới đích, nêu rõ tệp bị đọc và địa chỉ nhận.

## B.9 Giai đoạn 8 — Đánh giá hàng loạt

Với quy mô corpus, `benchmark.js` điều khiển toàn bộ quy trình trên cả hai bộ dữ
liệu bằng một nhóm tiến trình xử lý có giới hạn. Kết quả được ghi theo luồng ra tệp
CSV và JSONL ngay khi từng mẫu hoàn tất, nên một lần chạy bị gián đoạn có thể được
tiếp tục. Ma trận nhầm lẫn được tính theo cả hai quy tắc quyết định, đồng thời phân
tầng theo tầng bằng chứng và theo lý do gỡ bỏ. Mọi dương tính giả và âm tính giả đều
được quy về một trong tám nguyên nhân có tên gọi cụ thể.

## B.10 Quy trình vận hành

**Kiểm chứng cài đặt.** Lệnh sau đây dựng một mẫu mã độc tổng hợp có chặn theo hệ
điều hành và bom hẹn giờ chín mươi ngày, kích nổ nó, và khẳng định rằng cả tín hiệu
gửi ra lẫn luồng dữ liệu đã chứng minh đều được ghi nhận:

```
node VEXGuard.js --selftest
```

**Phân tích một tiện ích đơn lẻ:**

```
node VEXGuard.js <đường-dẫn-tới-tiện-ích.vsix>
```

**Đánh giá toàn bộ corpus:**

```
node benchmark.js --datasets all --concurrency 8 --timeout 120000
```

**Các tuỳ chọn chính:**

| Tuỳ chọn | Tác dụng |
|---|---|
| `--datasets all\|datadog\|vsmex` | Chọn bộ dữ liệu cần phân tích |
| `--concurrency N` | Số mẫu được phân tích song song |
| `--timeout MS` | Giới hạn thời gian kích nổ cho mỗi mẫu |
| `--limit N` | Giới hạn số mẫu mỗi corpus, dùng cho lần chạy kiểm chứng ngắn |
| `--latest-only` | Chỉ giữ phiên bản mới nhất của mỗi tiện ích |
| `--tiers` / `--exclude-tiers` | Giới hạn phân tích theo tầng bằng chứng đã chọn |
| `--resume` | Bỏ qua các mẫu đã có trong tệp kết quả |
| `--report-only` | Sinh lại báo cáo từ kết quả sẵn có mà không phân tích lại |
