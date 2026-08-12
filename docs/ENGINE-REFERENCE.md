# VEXGuard — VS Code Extension Guard  (v3)

A unified engine for detecting malicious VS Code (`.vsix`) extensions. `VEXGuard.js`
is the **single entrypoint** that ties every layer of the pipeline together behind
one clean API + CLI, and is built to stay **open** for a future UI and LLM.

> Project: CSN 304 — *"Towards Identifying Malicious VS Code Extensions."*

---

## What VEXGuard does

For any extension (a `.vsix` file or an unpacked folder) it runs a **two-stage**
analysis and returns one explainable verdict plus a forensic report:

1. **Static pre-filter** (`preprocess.js`) — unpacks, de-obfuscates, parses to an
   **AST**, and judges call *shapes* rather than keywords: `eval` is judged by what
   it evaluates, `child_process` by whether its command is constructed, `fs` writes
   by their destination, and a download-and-execute cradle by whether one command
   string both fetches a remote payload and runs it.
2. **Dynamic detonation** (`sandbox.js`) — runs the extension inside
   `vm.createContext()` with hooked `child_process` / `http` / `net` / `fs` / …, a
   **decoy victim profile** full of bait secrets, a full **VS Code event sweep**
   (27 lifecycle events), the **Time Machine** virtual clock (fast-forwards up to
   **366 days** so time-gated payloads fire instantly), spoofed `win32` platform and
   environment, and **anti-analysis `toString()` cloaking** so malware cannot detect
   the hooks.
3. **Closed-loop taint** (`data-intel.js`) — a `MALICIOUS` exfiltration claim
   requires a proven **source → sink** flow: bytes read from a sensitive location
   turning up in bytes being transmitted. Pattern-only resemblance is reported as
   *suspected*, never as theft.
4. **Combined verdict** — `FINAL = max(static, dynamic)`, plus **cross-modality
   corroboration**: when static and dynamic independently land on the *same
   indicator family*, two sub-threshold SUSPICIOUS findings escalate to MALICIOUS.
5. **Forensic report** — MITRE ATT&CK-mapped behavioural narrative + IOCs + the
   proven data flows.

The heavy analysis engines run as **subprocesses** — process isolation is a security
feature when executing untrusted code.

---

## Files

| File | Role |
|------|------|
| `VEXGuard.js` | Orchestrator, verdict engine, batch runner, CLI |
| `benchmark.js` | Evaluation driver: confusion matrices + root-cause report |
| `dataset.js` | Corpus ingestion + ground-truth resolution (DataDog + VsMex) |
| `preprocess.js` | Static AST-first pre-filter |
| `sandbox.js` | Dynamic detonation harness |
| `data-intel.js` | Sensitive-data classification + closed-loop taint |
| `mock-vscode.js` | VS Code API simulation (full event registry) |
| `time-machine.js` | Virtual clock / fast-forward scheduler |
| `decoy-profile.js` | Synthetic victim profile (honeypot secrets) |
| `native-spoof.js` | `Function.prototype.toString` cloaking |
| `zip-util.js` | Dependency-free ZIP/VSIX reader |

---

## Install & quickstart

```bash
npm install acorn
```

Node ≥ 18. `acorn` is what powers the AST layer — without it the static stage
degrades to regex matching, which is measurably more false-positive-prone.

Prove the checkout works (builds an OS-gated, 90-day time-bombed stealer and
detonates it end to end):

```bash
node VEXGuard.js --selftest
```

Scan one extension:

```bash
node VEXGuard.js path/to/extension.vsix
```

---

## Batch scanning & evaluation

Both corpora, full metrics and root-cause report:

```bash
node benchmark.js --datasets all --concurrency 8
```

Or via the launchers:

```powershell
.\Run-VEXGuard.ps1 -Datasets all -Concurrency 8
```

```bat
VEXGuard_run.bat
```

### benchmark.js flags

| Flag | Meaning |
|------|---------|
| `--datasets all\|datadog\|vsmex` | which corpora to run |
| `--concurrency N` | parallel samples (default: cpus−1, capped at 8) |
| `--limit N` | cap samples per corpus (smoke test) |
| `--latest-only` | newest version per extension (VsMex ships up to 5 per extension) |
| `--tiers code,suspect` | analyse ONLY these evidence tiers (VsMex) |
| `--exclude-tiers policy` | drop these evidence tiers (VsMex) |
| `--static-only` | skip detonation |
| `--resume` | skip samples already in the results CSV |
| `--report-only` | rebuild reports from existing CSVs |
| `--timeout MS` | per-sample detonation timeout |
| `--out DIR` | results directory |

### Outputs

| File | Contents |
|------|----------|
| `results-<corpus>.csv` | one row per sample (streamed, resumable) |
| `results-<corpus>.jsonl` | full evidence per sample |
| `METRICS.md` | confusion matrices, stratified |
| `ROOT-CAUSE.md` | per-sample diagnosis of every FP and FN |
| `metrics.json` | machine-readable metrics |

---

## Dataset layouts understood

`dataset.js` auto-detects the layout, resolves ground truth, and **never descends
into `node_modules`** (one extension can ship thousands of nested `package.json`
files; treating each as a sample was the reason earlier batch runs produced rows
named `node-fetch` and `fetch-blob`).

**DataDog** (`Dataset_Malicious/`, `Dataset_Benign/`)
```
<publisher>.<name>/<version>.vsix
<publisher>.<name>/<version>/extension/package.json      (pre-unpacked)
Sample/Sample/<publisher>.<name>-<version>.vsix
```
Label: the tree the sample lives in.

**VsMex** (Alachkar et al., CODASPY '26)
```
extensions/<publisher>.<name>/<version>/<publisher>.<name>-<version>.vsix
metadata/vsmex_metadata.csv                  per (extension, version)
metadata/msft_vscode_flagged_extensions.csv  per extension
```
Label: Microsoft's own `msft_classification_type`.

When both a `.vsix` and a pre-unpacked directory exist for the same sample the
`.vsix` wins — it is the pristine artefact, whereas unpacked trees carry
`execution-log.json` / `static-analysis.json` left by earlier runs.

---

## Two decision rules, always reported together

| Rule | Positive class | Use |
|------|----------------|-----|
| **STRICT** | verdict = `MALICIOUS` | auto-block / removal decisions |
| **TRIAGE** | `MALICIOUS` or `SUSPICIOUS` | analyst review queue |

Reporting only one is misleading: STRICT is the precision number you would act on
automatically, TRIAGE is what an analyst queue would surface.

---

## Why VsMex is stratified

VsMex is a dataset of extensions **removed by Microsoft**, not a dataset of malware.
Roughly 47% were removed for brand **impersonation**, copyright or spam — policy
violations whose code is frequently a verbatim clone of the legitimate extension,
with nothing hostile in the bundle to find. `benchmark.js` therefore reports:

* **CODE-LEVEL matrix** — `Malware` / `Malicious` / `Potentially malicious` only,
  plus the benign controls. The primary result.
* **FULL matrix** — every removed extension counted as malicious. The pessimistic
  bound.
* **Per-removal-reason breakdown**, so the gap is visible and attributable.

Detecting impersonation needs publisher reputation and marketplace metadata, which
this engine deliberately does not model.

`--tiers` / `--exclude-tiers` let a run target one population directly. **Use them
to answer a scoped question, not to improve a headline.** On this corpus the
`policy` tier is not inert: 272 of its 1,774 samples were independently scored
MALICIOUS on code evidence, so excluding the tier discards 272 genuine detections
along with the unreachable ones. The default remains "analyse everything, report
stratified", which keeps the out-of-scope population visible and attributable
rather than quietly deleted.

---

## Embedding / extension points

```js
const { VEXGuard } = require('./VEXGuard');

const vg = new VEXGuard({ platform: 'win32', fast: true });
vg.on('sample:done', (r) => console.log(r.sample, r.final.verdict));

const result = await vg.analyze('path/to/ext.vsix');
```

Swap either engine for an LLM — both may be async:

```js
new VEXGuard({
  verdictEngine:  { async classify(evidence) { /* → {verdict, is_malicious, score, reasons} */ } },
  forensicEngine: { async report(evidence, verdict) { /* → {behaviours, iocs, markdown} */ } },
});
```

`VEXGuard.digest(evidence)` produces a compact, promptable summary of all evidence
(static IOCs, hosts, commands, outbound bodies, proven taint flows) suitable for a
model context.

Events: `sample:start`, `static:done`, `dynamic:done`, `verdict`, `forensic`,
`sample:done`, `dataset:start`, `dataset:progress`, `dataset:done`, `error`.

---

## Environment knobs (sandbox)

| Variable | Default | Meaning |
|----------|---------|---------|
| `SANDBOX_OS` | `win32` | spoofed `process.platform` / `os.platform()` |
| `SANDBOX_ARCH` | `x64` | spoofed architecture |
| `SANDBOX_FAST` | off | collapse harness settle waits (batch mode) |
| `SANDBOX_MAX_VIRTUAL_MS` | 366 d | Time Machine horizon |
| `SANDBOX_MAX_TIMERS` | 20000 | cap on virtual timer fires |
| `SANDBOX_MAX_TICKS` | 150 | cap on repeats per `setInterval` |
| `SANDBOX_MAX_EVENTS` | 4000 | cap on stored log events |
| `SANDBOX_MAX_CMDS` | 60 | cap on simulated command invocations |

---

## Safety notes

* Untrusted code runs in a child process, inside `vm.createContext()`, with every
  I/O module hooked: writes are blocked, network calls are mocked, processes are
  never spawned.
* `os.homedir()` and the Windows environment point at a throw-away **decoy
  profile**, so a stealer harvests fabricated secrets and never reaches the
  analyst's real keys. The profile is deleted after each run.
* Every decoy value is structurally invalid and authenticates against nothing.
