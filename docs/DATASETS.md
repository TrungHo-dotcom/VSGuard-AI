# Dataset Structures — VsMex vs. DataDog

Reference for `dataset.js`, the ingestion module. Everything below was derived by
reading the corpora on disk and their `README.md` files.

---

## 1. VsMex (Alachkar, Gaastra, Gadyatskaya, Barbaro, van Eeten, Zhauniarovich — CODASPY '26)

> *"VSMEx: A Collection Tool and a Dataset of Malicious VS Code Extensions"*,
> Proc. 16th ACM CODASPY, pp. 138–144. DOI 10.1145/3800506.3803487

### What it is

A collection **tool** plus a **dataset** of VS Code extensions that **Microsoft
removed from the Marketplace**. The public GitHub repo (`vsmex-main/`) ships only
the crawler and the metadata CSVs; the VSIX packages themselves are distributed
separately to approved institutional researchers via SURFfilesender. Both halves
are present in this workspace.

### On-disk layout

```
vsmex-main/                                  ← the public repo (tooling only)
├── tool/
│   ├── crawler.py          crawls the Marketplace, stores new VSIX files
│   ├── vsmex.py            reads Microsoft's flagged lists → dataset + metadata
│   ├── config.py
│   └── v1-azure/           archived earlier versions
├── metadata/               (empty in this checkout)
└── docs/                   (empty in this checkout)

vsmex-dataset/                               ← the restricted data drop
├── README.md
└── vsmex-dataset/
    ├── extensions/
    │   └── <publisher>.<name>/
    │       └── <version>/
    │           └── <publisher>.<name>-<version>.vsix
    └── metadata/
        ├── msft_vscode_flagged_extensions.csv    1,852 rows (one per extension)
        └── vsmex_metadata.csv                    3,791 rows (one per version)
```

**Format:** packaged `.vsix` archives only — nothing is pre-extracted. Three
directory levels carry identity: publisher.name → version → artefact.

**Scale in this checkout:** 1,609 extension directories, **3,790 `.vsix` files**
(up to five versions per extension).

### Metadata schemas

`msft_vscode_flagged_extensions.csv` — one row per extension:
`source`, `checked_date`, `extension_identifier`, `msft_classification_type`,
`msft_removed_date`, `captured`, `version_count`, `latest_version`, `capture_date`

`vsmex_metadata.csv` — one row per (extension, version):
`captured_date`, `source`, `msft_classification_type`, `extension_identifier`,
`publisher_name`, `version`, `artifact`, `sha256`, `size_mb`, `published_date`,
`last_updated_date`, `verified_publisher`, `installation_count`, `average_rating`,
`rating_count`, `categories`, `repository_url`, `flags`, `engines_vscode`,
`exists_in_dataset`

### The label problem — the single most important finding

**VsMex is not a malware dataset. It is a *removal* dataset.** `msft_classification_type`
records *why* Microsoft pulled the extension, and the distribution over the 3,790
artefacts in this checkout is:

| `msft_classification_type` | artefacts | evidence tier |
|---|---:|---|
| Impersonation (+ `impersonation`) | 1,568 | policy |
| Malware | 1,122 | **code** |
| Untrustworthy | 762 | suspect |
| Spam | 174 | policy |
| Malicious | 106 | **code** |
| Copyright violation | 14 | policy |
| Spam / Malware | 14 | **code** |
| Owner Request | 8 | policy |
| Publisher requested | 6 | policy |
| Impersonation;Malware | 5 | **code** |
| Potentially malicious | 4 | **code** |
| Deprecated | 2 | policy |
| Typo-squatting | 1 | policy |
| Expired domain | 1 | policy |
| *(not in metadata)* | 3 | unknown |

Grouped: **code 1,251 · suspect 762 · policy 1,774 · unknown 3.**

Roughly **47% were removed for policy reasons, not hostile code.** An impersonating
extension is usually a *verbatim clone* of the legitimate one — there is nothing in
the bundle for a static or behavioural engine to detect. Catching those requires
publisher reputation and marketplace signals, which VEXGuard deliberately does not
model.

`dataset.js` therefore assigns each sample an **evidence tier**
(`code` / `suspect` / `policy`), and `benchmark.js` reports a code-level matrix as
the primary result plus a full-corpus matrix as the pessimistic bound. Pooling all
1,852 extensions into one matrix would attribute an out-of-scope failure to the
detector and understate recall by roughly a factor of two.

Where a cell carries several reasons (`Impersonation;Malware`, `Spam / Malware`)
the **strongest** tier wins, so a sample flagged for both impersonation and malware
still counts as code-level.

---

## 2. DataDog (`Dataset_Malicious/`, `Dataset_Benign/`)

Derived from Datadog Security Labs' *Open-Source Dataset of Malicious Software
Packages* (28,623 packages across npm, PyPI, IDE extensions, AI Skills; most
identified by GuardDog, every sample human-triaged). The IDE-extension slice has
been extracted here; the upstream repo distributes samples as ZIPs encrypted with
the password `infected`, but in this workspace they are already decrypted.

### On-disk layout

```
Dataset_Malicious/Dataset_Malicious/
├── README.md                                ← the upstream Datadog README
├── <publisher>.<name>/
│   ├── <version>.vsix                       ← packaged artefact
│   ├── static-analysis.json                 ← left by earlier VEXGuard runs
│   └── <version>/                           ← SOME samples also pre-extracted
│       ├── extension/
│       │   ├── package.json
│       │   ├── node_modules/                ← ships bundled dependencies
│       │   └── …
│       ├── extension.vsixmanifest
│       └── [Content_Types].xml
└── Sample/Sample/
    └── <publisher>.<name>-<version>.vsix    ← loose extras, different naming

Dataset_Benign/Dataset_Benign/
└── <publisher>.<name>/
    └── <version>.vsix
```

**Scale:** malicious — 103 extension dirs, **123 `.vsix`**, 29 pre-extracted trees;
benign — 49 extension dirs, **49 `.vsix`** (top-installed marketplace extensions).

**Labels** come from the corpus itself: everything under a `*_Malicious` tree is a
confirmed malicious package, everything under `*_Benign` is a benign control. No
metadata file is needed. The upstream `manifest.json` convention (`null` ⇒ all
versions malicious; otherwise a list of compromised versions) is not present in this
slice.

---

## 3. Structural differences that ingestion has to absorb

| | DataDog | VsMex |
|---|---|---|
| Artefact | `.vsix` + *some* pre-extracted trees | `.vsix` only |
| Version in path | `<id>/<version>.vsix` | `<id>/<version>/<id>-<version>.vsix` |
| Identity source | parent directory name | file name **and** grandparent |
| Ground truth | directory tree | `msft_classification_type` CSV |
| Label granularity | package | package (but *reason* varies per extension) |
| Negatives present | yes (49 benign) | **no** — every sample is a removal |
| Versions per extension | 1–5 | 1–5 |
| Bundled `node_modules` | yes, inside extracted trees | inside the `.vsix` |

Three consequences for `dataset.js`:

1. **`node_modules` is never descended when discovering samples.** One extension can
   ship thousands of nested `package.json` files. Walking them produced the junk
   result rows named `node-fetch`, `fetch-blob` and `hardhat` in the previous batch
   runs, and re-scanned the same extension dozens of times.
   *(The static engine still reads inside `node_modules` — that is how the ETHCode
   trojan hidden in `keythereum-utils` is caught. The exclusion is about what counts
   as a **sample**, not about what gets scanned.)*

2. **`.vsix` wins over a pre-extracted directory** for the same sample. The archive
   is the pristine artefact; extracted trees in `Dataset_Malicious` are polluted with
   `execution-log.json` and `static-analysis.json` from earlier runs.

3. **VsMex has no negatives.** Precision is undefined on VsMex alone, so
   `benchmark.js` folds the 49 DataDog benign controls into the VsMex matrices.

### Known corpus quirk — 13 double-filed artefacts

Thirteen `.vsix` files appear under two different extension directories, e.g.

```
extensions/devsessioncanvas.dev-session-canvas/0.5.0/devsessioncanvas.dev-session-canvas-notifier-0.5.0.vsix
extensions/devsessioncanvas.dev-session-canvas-notifier/0.5.0/devsessioncanvas.dev-session-canvas-notifier-0.5.0.vsix
```

The directory says `dev-session-canvas`; the artefact inside says
`dev-session-canvas-notifier`. `identify()` trusts the artefact filename (it is
the authoritative `<id>-<version>` produced by the packer), so both paths resolve
to the same identity and the sample is analysed twice.

This is left as-is rather than "fixed": both files really are in the corpus, both
carry the same Microsoft classification, and suppressing one would mean choosing
between two equally valid directory names. The effect is 3,790 analysed artefacts
across 3,777 distinct (extension, version) pairs — **0.3%**, immaterial to the
metrics. It is noted here so the row-count discrepancy is not mistaken for a
dedup bug.

---

## 4. Toolchain note

Neither `unzip` nor a working `python3` exists on the Windows analysis host — the
`python3` on `PATH` is the Microsoft Store App-Execution-Alias stub, which extracts
nothing. Every stage previously shelled out to one of those two, so **every `.vsix`
silently failed to open** and only the handful of pre-extracted DataDog samples were
ever really analysed. `zip-util.js` now reads the ZIP container directly with
`zlib.inflateRawSync`, so the engine has no external dependencies and behaves
identically across platforms.
