#!/usr/bin/env node
'use strict';
/**
 * benchmark.js — Automated Evaluation, Confusion Matrices & Root-Cause Report
 * ===========================================================================
 * Runs VEXGuard across BOTH corpora concurrently and emits everything the
 * write-up needs:
 *
 *   results-<dataset>.csv        one row per sample (streamed, resumable)
 *   results-<dataset>.jsonl      full evidence per sample
 *   metrics.json                 every confusion matrix, machine-readable
 *   METRICS.md                   the report tables
 *   ROOT-CAUSE.md                per-sample diagnosis of every FP and FN
 *
 * TWO DECISION RULES ARE REPORTED, always side by side:
 *
 *   STRICT  positive = MALICIOUS.          The headline precision number: what
 *                                          you would auto-block on.
 *   TRIAGE  positive = MALICIOUS or        What an analyst queue would surface.
 *           SUSPICIOUS.                    Recall matters more than precision here.
 *
 * WHY VsMex IS STRATIFIED
 * -----------------------
 * VsMex is a dataset of extensions REMOVED BY MICROSOFT, and roughly half were
 * removed for brand IMPERSONATION, copyright or spam — policy violations whose
 * code is often a verbatim clone of the legitimate extension. There is nothing
 * hostile in the bundle for a static or behavioural engine to find; catching
 * them requires publisher reputation and marketplace metadata, which this
 * engine does not model. Reporting one pooled matrix over all 1 850 extensions
 * would therefore understate recall by attributing an out-of-scope failure to
 * the detector. We report:
 *
 *   • CODE-LEVEL matrix   (Malware / Malicious / Potentially malicious) — the
 *     primary result, the population this engine is designed for.
 *   • FULL matrix         (every removed extension) — the pessimistic bound.
 *   • A per-classification breakdown so the gap is visible and attributable.
 *
 * Usage:
 *   node benchmark.js                          # both corpora, defaults
 *   node benchmark.js --limit 50               # smoke test
 *   node benchmark.js --latest-only            # newest version per extension
 *   node benchmark.js --concurrency 8 --resume
 *   node benchmark.js --datasets datadog       # datadog | vsmex | all
 *   node benchmark.js --report-only            # rebuild reports from existing CSVs
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { VEXGuard } = require('./VEXGuard');
const DATASET = require('./dataset');

const ROOT = path.resolve(__dirname, '..');

/** Default corpus locations, relative to the project root. */
const CORPORA = [
  { key: 'datadog-malicious', dir: path.join(ROOT, 'Dataset_Malicious'), label: 1, group: 'datadog' },
  { key: 'datadog-benign',    dir: path.join(ROOT, 'Dataset_Benign'),    label: 0, group: 'datadog' },
  { key: 'vsmex',             dir: path.join(ROOT, 'vsmex-dataset'),     label: 1, group: 'vsmex' },
];

const pct  = (x) => `${(100 * (x || 0)).toFixed(1)}%`;
const safe = (s) => String(s).replace(/[^a-zA-Z0-9._-]/g, '_');

function parseArgs(argv) {
  const a = { flags: {} };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) continue;
    const key = k.slice(2), next = argv[i + 1];
    if (next && !next.startsWith('--')) { a.flags[key] = next; i++; } else a.flags[key] = true;
  }
  return a;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Metrics
// ─────────────────────────────────────────────────────────────────────────────

function matrix(rows, predKey) {
  let TP = 0, FP = 0, FN = 0, TN = 0, errors = 0;
  for (const r of rows) {
    const y = Number(r.label);
    if (y !== 0 && y !== 1) continue;
    if (r.final_verdict === 'ERROR') errors++;
    const p = Number(r[predKey]) ? 1 : 0;
    if (y === 1 && p === 1) TP++;
    else if (y === 0 && p === 1) FP++;
    else if (y === 1 && p === 0) FN++;
    else TN++;
  }
  const precision = TP + FP ? TP / (TP + FP) : 0;
  const recall    = TP + FN ? TP / (TP + FN) : 0;
  const f1        = precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  const total     = TP + FP + FN + TN;
  const accuracy  = total ? (TP + TN) / total : 0;
  // Matthews correlation — honest on the imbalanced pooled sets, where accuracy
  // alone flatters any detector that simply says "malicious" a lot.
  const denom = Math.sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN));
  const mcc   = denom ? ((TP * TN) - (FP * FN)) / denom : 0;
  return { TP, FP, FN, TN, total, errors, precision, recall, f1, accuracy, mcc };
}

function bothRules(rows) {
  return { strict: matrix(rows, 'final_is_malicious'), triage: matrix(rows, 'final_is_flagged') };
}

function mdMatrix(m) {
  return [
    '|              | Predicted POSITIVE | Predicted NEGATIVE |',
    '|--------------|--------------------|--------------------|',
    `| **Actual MALICIOUS** | TP = ${m.TP} | FN = ${m.FN} |`,
    `| **Actual BENIGN**    | FP = ${m.FP} | TN = ${m.TN} |`,
    '',
    `Precision **${pct(m.precision)}** · Recall **${pct(m.recall)}** · F1 **${pct(m.f1)}** · Accuracy **${pct(m.accuracy)}** · MCC **${m.mcc.toFixed(3)}** · n = ${m.total}`,
  ].join('\n');
}

// ─────────────────────────────────────────────────────────────────────────────
//  Root-cause classification
//  Every FP and FN gets a named, actionable cause — not "it was wrong", but
//  WHICH stage failed and what would have to change to fix it.
// ─────────────────────────────────────────────────────────────────────────────

function diagnoseFN(r) {
  const events = Number(r.total_events) || 0;
  const net    = Number(r.http_requests) || 0;
  const exec   = Number(r.child_process_calls) || 0;
  const timers = Number(r.timers_fired) || 0;
  const staticFlagged = r.static_verdict && r.static_verdict !== 'BENIGN';

  if (r.final_verdict === 'ERROR')
    return { cause: 'ANALYSIS_ERROR', detail: `The sample could not be analysed (${r.error || 'unknown error'}). Not a detection failure — fix ingestion/unpacking and re-run.` };

  if (String(r.timed_out) === '1')
    return { cause: 'TIMEOUT', detail: 'Detonation was killed by the per-sample timeout before behaviour surfaced. Mitigation: raise --timeout, or lower SANDBOX_MAX_CMDS for command-heavy samples.' };

  if (r.tier === 'policy')
    return { cause: 'OUT_OF_SCOPE_POLICY_REMOVAL', detail: `Microsoft removed this for "${r.classification}" — brand impersonation / copyright / spam. The bundle usually contains no hostile code, so no static or behavioural engine can flag it. Requires publisher reputation + marketplace metadata.` };

  if (r.tier === 'suspect')
    return { cause: 'OUT_OF_SCOPE_UNTRUSTWORTHY', detail: 'Microsoft classified this as "Untrustworthy" — a risk judgement rather than an assertion of malicious code. Frequently no observable payload exists.' };

  if (r.final_verdict === 'SUSPICIOUS')
    return { cause: 'BELOW_MALICIOUS_THRESHOLD', detail: `Evidence was found but scored ${r.score}, below the MALICIOUS bar. It IS caught by the TRIAGE rule. Mitigation: raise the weight of the contributing indicators, or treat SUSPICIOUS as positive.` };

  if (events === 0 && !staticFlagged)
    return { cause: 'DORMANT_NO_OBSERVABLE_PAYLOAD', detail: 'The extension executed nothing observable and carries no static IOC — a clean re-publish, a first-stage placeholder awaiting a server-side trigger, or a payload gated behind a condition the simulator does not reproduce (specific workspace contents, a live C2 response, a real user credential).' };

  if (events === 0 && staticFlagged)
    return { cause: 'GATED_STATIC_ONLY', detail: `Nothing ran, but static did see indicators (${r.static_verdict}, score ${r.static_score}). The payload is gated. Mitigation: extend the simulator's trigger surface, or lower the static MALICIOUS bar for this indicator class.` };

  if (net > 0 && exec === 0 && Number(r.data_stolen) === 0)
    return { cause: 'NETWORK_ONLY_INDISTINGUISHABLE', detail: `Contacted the network (${net} request(s)) but to no known-bad destination, and no read→send taint loop closed. Behaviourally identical to a legitimate telemetry or AI-assistant extension at observation time. This is the hard residue: separating it needs endpoint reputation.` };

  if (timers === 0 && events > 0)
    return { cause: 'RAN_BUT_UNRECOGNISED', detail: 'Runtime activity occurred but matched no malicious signature. Mitigation: add a rule for the observed behaviour, or route the evidence digest to an LLM verdict engine.' };

  return { cause: 'UNRECOGNISED_BEHAVIOUR', detail: `Observed ${events} event(s) that no rule scored as malicious. Review the sample's execution-log.json.` };
}

function diagnoseFP(r) {
  const reasons = String(r.top_reasons || '');
  const pick = (re, cause, detail) => (re.test(reasons) ? { cause, detail } : null);
  return pick(/cradle/i, 'CRADLE_OVERMATCH',
              'The download-and-execute rule matched a command string that is not a cradle. Tighten isCradleLiteral(): the LOLBIN, the remote payload and the execution verb must all be present in one command.')
      || pick(/reverse shell/i, 'REVERSE_SHELL_OVERMATCH',
              'Socket + child_process co-occurrence matched a language-server/debug-adapter client. Require the structural wiring (a socket data handler that executes its input) rather than co-occurrence.')
      || pick(/exfiltrat/i, 'TAINT_OVERMATCH',
              'The taint layer confirmed a flow that is legitimate (an AI assistant uploading the open document). Downgrade the category to weakOnly in data-intel.js so a line-level match cannot confirm it.')
      || pick(/recon/i, 'RECON_OVERMATCH',
              'The reconnaissance battery matched a telemetry library (e.g. systeminformation). Require at least one account/privilege-level probe, not only network enumeration.')
      || pick(/eval/i, 'EVAL_OVERMATCH',
              'eval/new Function over "decoded" data matched ordinary bundler output. Narrow DECODER_NAMES in preprocess.js.')
      || pick(/invisible-Unicode/i, 'UNICODE_OVERMATCH',
              'Invisible-codepoint counting matched a Unicode data table or an emoji tag sequence. Raise GLASSWORM_MIN_RUN or extend the emoji-tag exclusion.')
      || pick(/raw public IP/i, 'RAW_IP_OVERMATCH',
              'A hard-coded IP matched a legitimate service or a test fixture. Allowlist well-known infrastructure ranges.')
      || { cause: 'RULE_OVERMATCH', detail: `Flagged by: ${reasons.slice(0, 300)}. Review the contributing rule's specificity.` };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Report writers
// ─────────────────────────────────────────────────────────────────────────────

function tierBreakdown(rows) {
  const byTier = {};
  for (const r of rows) {
    const t = r.tier || 'unknown';
    byTier[t] = byTier[t] || { n: 0, malicious: 0, flagged: 0, benign: 0, error: 0 };
    byTier[t].n++;
    if (r.final_verdict === 'MALICIOUS') { byTier[t].malicious++; byTier[t].flagged++; }
    else if (r.final_verdict === 'SUSPICIOUS') byTier[t].flagged++;
    else if (r.final_verdict === 'ERROR') byTier[t].error++;
    else byTier[t].benign++;
  }
  return byTier;
}

function classBreakdown(rows) {
  const by = {};
  for (const r of rows) {
    const c = r.classification || '(none)';
    by[c] = by[c] || { n: 0, malicious: 0, flagged: 0 };
    by[c].n++;
    if (r.final_verdict === 'MALICIOUS') { by[c].malicious++; by[c].flagged++; }
    else if (r.final_verdict === 'SUSPICIOUS') by[c].flagged++;
  }
  return by;
}

function writeMetrics(outDir, report) {
  fs.writeFileSync(path.join(outDir, 'metrics.json'), JSON.stringify(report, null, 2));

  const L = [];
  L.push('# VEXGuard — Evaluation Report', '');
  L.push(`Generated: ${report.generated_at}`);
  L.push(`Engine: static ${report.versions.static} · sandbox ${report.versions.sandbox} · orchestrator ${report.versions.orchestrator}`, '');
  L.push('## Decision rules', '');
  L.push('| Rule | Positive class | Use |');
  L.push('|------|----------------|-----|');
  L.push('| **STRICT** | verdict = MALICIOUS | auto-block / removal decisions |');
  L.push('| **TRIAGE** | verdict = MALICIOUS or SUSPICIOUS | analyst review queue |');
  L.push('');

  for (const section of report.sections) {
    L.push(`## ${section.title}`, '');
    if (section.note) L.push(`> ${section.note}`, '');
    L.push(`Samples: **${section.n}**  ·  malicious-labelled: ${section.positives}  ·  benign-labelled: ${section.negatives}`, '');
    L.push('### STRICT (positive = MALICIOUS)', '', mdMatrix(section.strict), '');
    L.push('### TRIAGE (positive = MALICIOUS or SUSPICIOUS)', '', mdMatrix(section.triage), '');
    if (section.tiers) {
      L.push('### Verdict distribution by evidence tier', '');
      L.push('| Tier | n | MALICIOUS | SUSPICIOUS+ | BENIGN | ERROR | strict detection rate |');
      L.push('|------|---|-----------|-------------|--------|-------|----------------------|');
      for (const [t, v] of Object.entries(section.tiers))
        L.push(`| ${t} | ${v.n} | ${v.malicious} | ${v.flagged} | ${v.benign} | ${v.error} | ${pct(v.malicious / Math.max(1, v.n))} |`);
      L.push('');
    }
    if (section.classes) {
      L.push('### Detection rate by Microsoft removal reason', '');
      L.push('| Removal reason | n | MALICIOUS | flagged | strict rate | triage rate |');
      L.push('|----------------|---|-----------|---------|-------------|-------------|');
      for (const [c, v] of Object.entries(section.classes).sort((a, b) => b[1].n - a[1].n))
        L.push(`| ${c} | ${v.n} | ${v.malicious} | ${v.flagged} | ${pct(v.malicious / Math.max(1, v.n))} | ${pct(v.flagged / Math.max(1, v.n))} |`);
      L.push('');
    }
  }

  L.push('## Corpus inventory', '');
  L.push('| Dataset | discovered | analysed | .vsix | unpacked dirs |');
  L.push('|---------|-----------|----------|-------|---------------|');
  for (const d of report.datasets)
    L.push(`| ${d.dataset} | ${d.stats.total_discovered} | ${d.analysed} | ${d.stats.vsix_found} | ${d.stats.unpacked_dirs_found} |`);
  L.push('');
  fs.writeFileSync(path.join(outDir, 'METRICS.md'), L.join('\n'));
}

function writeRootCause(outDir, allRows) {
  const fps = allRows.filter((r) => Number(r.label) === 0 && Number(r.final_is_malicious) === 1);
  const fns = allRows.filter((r) => Number(r.label) === 1 && Number(r.final_is_malicious) === 0);
  const errs = allRows.filter((r) => r.final_verdict === 'ERROR');

  const group = (list, fn) => {
    const m = new Map();
    for (const r of list) {
      const d = fn(r);
      if (!m.has(d.cause)) m.set(d.cause, { detail: d.detail, rows: [] });
      m.get(d.cause).rows.push(r);
    }
    return [...m.entries()].sort((a, b) => b[1].rows.length - a[1].rows.length);
  };

  const L = [];
  L.push('# VEXGuard — Root-Cause Analysis of Residual FP / FN', '');
  L.push(`Generated: ${new Date().toISOString()}`, '');
  L.push(`False positives: **${fps.length}** · False negatives: **${fns.length}** · Analysis errors: **${errs.length}**`, '');
  L.push('Every misclassification below is attributed to a named cause with the specific');
  L.push('change that would address it. Causes prefixed `OUT_OF_SCOPE_` are dataset-labelling');
  L.push('artefacts rather than engine defects — see METRICS.md for why VsMex is stratified.', '');

  L.push('---', '', '## FALSE POSITIVES — benign flagged as MALICIOUS', '');
  if (!fps.length) L.push('_None._', '');
  for (const [cause, g] of group(fps, diagnoseFP)) {
    L.push(`### ${cause}  (${g.rows.length})`, '', `**Fix:** ${g.detail}`, '');
    for (const r of g.rows) {
      L.push(`- ⚠️ **${r.id}** v${r.version} — score ${r.score}, decided by ${r.decided_by}`);
      if (r.top_reasons) L.push(`  - reasons: ${String(r.top_reasons).slice(0, 300)}`);
    }
    L.push('');
  }

  L.push('---', '', '## FALSE NEGATIVES — malicious not flagged as MALICIOUS', '');
  if (!fns.length) L.push('_None._', '');
  for (const [cause, g] of group(fns, diagnoseFN)) {
    L.push(`### ${cause}  (${g.rows.length})`, '', `**Cause:** ${g.detail}`, '');
    const show = g.rows.slice(0, 120);
    for (const r of show) {
      L.push(`- ❌ **${r.id}** v${r.version} → ${r.final_verdict}` +
             ` _(tier ${r.tier || '?'}${r.classification ? ', "' + r.classification + '"' : ''};` +
             ` events=${r.total_events} net=${r.http_requests} exec=${r.child_process_calls}` +
             ` timers=${r.timers_fired} static=${r.static_verdict})_`);
    }
    if (g.rows.length > show.length) L.push(`- … and ${g.rows.length - show.length} more (see the CSV)`);
    L.push('');
  }

  if (errs.length) {
    L.push('---', '', '## ANALYSIS ERRORS', '');
    for (const r of errs.slice(0, 100)) L.push(`- ⚠️ **${r.id}** v${r.version} — ${r.error}`);
    L.push('');
  }

  fs.writeFileSync(path.join(outDir, 'ROOT-CAUSE.md'), L.join('\n'));
  return { fps: fps.length, fns: fns.length, errors: errs.length };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Driver
// ─────────────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);
  const outDir = path.resolve(args.flags.out ? String(args.flags.out) : path.join(__dirname, 'vexguard-results'));
  fs.mkdirSync(outDir, { recursive: true });

  const want = String(args.flags.datasets || 'all').toLowerCase();
  const selected = CORPORA.filter((c) => (want === 'all' || c.group === want) && fs.existsSync(c.dir));
  if (!selected.length) { console.error(`No corpora found under ${ROOT} for --datasets ${want}`); process.exit(1); }

  const concurrency = args.flags.concurrency ? Number(args.flags.concurrency)
                                             : Math.max(2, Math.min(8, (os.cpus().length || 4) - 1));

  console.log('═'.repeat(72));
  console.log('  VEXGuard — BENCHMARK');
  console.log('═'.repeat(72));
  console.log(`  Corpora     : ${selected.map((s) => s.key).join(', ')}`);
  console.log(`  Concurrency : ${concurrency}`);
  console.log(`  Output      : ${outDir}`);
  if (args.flags.limit)       console.log(`  Limit       : ${args.flags.limit} per corpus`);
  if (args.flags['latest-only']) console.log('  Versions    : latest per extension only');
  if (args.flags['static-only']) console.log('  Stages      : STATIC ONLY (no detonation)');
  console.log('═'.repeat(72));

  const datasets = [];
  const allRows  = [];

  for (const corpus of selected) {
    const csvPath   = path.join(outDir, `results-${safe(corpus.key)}.csv`);
    const jsonlPath = path.join(outDir, `results-${safe(corpus.key)}.jsonl`);

    if (args.flags['report-only']) {
      if (!fs.existsSync(csvPath)) { console.log(`  (skip ${corpus.key}: no ${path.basename(csvPath)})`); continue; }
      const rows = DATASET.parseCsv(fs.readFileSync(csvPath, 'utf8'));
      const ds = DATASET.discover(corpus.dir, { label: corpus.label });
      datasets.push({ dataset: corpus.key, group: corpus.group, stats: ds.stats, analysed: rows.length, rows });
      allRows.push(...rows);
      console.log(`  ${corpus.key}: loaded ${rows.length} rows from CSV`);
      continue;
    }

    const vg = new VEXGuard({
      output: outDir,
      fast: true,
      timeout: args.flags.timeout ? Number(args.flags.timeout) : 90000,
      staticTimeout: args.flags['static-timeout'] ? Number(args.flags['static-timeout']) : 60000,
      platform: args.flags.platform ? String(args.flags.platform) : 'win32',
    });

    let t0 = Date.now();
    vg.on('dataset:start', (e) => {
      console.log(`\n▶ ${corpus.key}  —  ${e.total} to analyse (${e.skipped} already done)`);
      console.log(`  tiers: ${JSON.stringify(e.stats.tiers)}`);
      t0 = Date.now();
    });
    vg.on('dataset:progress', (e) => {
      const icon = e.row.final_verdict === 'MALICIOUS' ? '🔴' : e.row.final_verdict === 'SUSPICIOUS' ? '🟡'
                 : e.row.final_verdict === 'ERROR' ? '⚠️ ' : '🟢';
      const per  = (Date.now() - t0) / Math.max(1, e.i) / 1000;
      const eta  = ((e.total - e.i) * per / 60).toFixed(1);
      process.stdout.write(`  [${String(e.i).padStart(5)}/${e.total}] ${icon} ${String(e.row.id).slice(0, 44).padEnd(44)} ${String(e.row.final_verdict).padEnd(10)} ${per.toFixed(1)}s/ea eta ${eta}m\n`);
    });

    const { rows, stats } = await vg.analyzeDataset(corpus.dir, {
      label:       corpus.label,
      datasetName: corpus.key,
      concurrency,
      limit:       args.flags.limit ? Number(args.flags.limit) : undefined,
      latestOnly:  !!args.flags['latest-only'],
      staticOnly:  !!args.flags['static-only'],
      resume:      !!args.flags.resume,
      // Tier filters apply to VsMex only — the DataDog corpora carry their
      // ground truth in the directory tree and have no removal-reason metadata.
      includeTiers: corpus.group === 'vsmex' && args.flags.tiers && args.flags.tiers !== true ? String(args.flags.tiers) : undefined,
      excludeTiers: corpus.group === 'vsmex' && args.flags['exclude-tiers'] && args.flags['exclude-tiers'] !== true ? String(args.flags['exclude-tiers']) : undefined,
      persist:     !!args.flags['keep-reports'],
      csv:         csvPath,
      jsonl:       jsonlPath,
    });
    datasets.push({ dataset: corpus.key, group: corpus.group, stats, analysed: rows.length, rows });
    allRows.push(...rows);
  }

  // ── Build report sections ─────────────────────────────────────────────────
  const rowsOf = (pred) => datasets.filter(pred).flatMap((d) => d.rows);
  const sections = [];

  const datadogRows = rowsOf((d) => d.group === 'datadog');
  if (datadogRows.length) {
    const b = bothRules(datadogRows);
    sections.push({
      title: 'DataDog corpus (Dataset_Malicious + Dataset_Benign)',
      note: 'Balanced ground truth from the corpus itself: every sample under the malicious tree is a confirmed malicious package, every sample under the benign tree is a top-installed marketplace extension. This is the primary precision/recall measurement.',
      n: datadogRows.length,
      positives: datadogRows.filter((r) => Number(r.label) === 1).length,
      negatives: datadogRows.filter((r) => Number(r.label) === 0).length,
      strict: b.strict, triage: b.triage, tiers: tierBreakdown(datadogRows),
    });
  }

  const vsmexRows  = rowsOf((d) => d.group === 'vsmex');
  const benignRows = rowsOf((d) => d.dataset === 'datadog-benign');
  if (vsmexRows.length) {
    // Code-level subset + the benign controls, so precision is measurable at all
    // (VsMex on its own contains no negatives).
    const codeRows = vsmexRows.filter((r) => r.tier === 'code').concat(benignRows);
    const bCode = bothRules(codeRows);
    sections.push({
      title: 'VsMex — CODE-LEVEL subset (primary)',
      note: 'Only extensions Microsoft removed as Malware / Malicious / Potentially malicious, plus the benign controls so precision is defined. This is the population a static+behavioural engine is built to detect.',
      n: codeRows.length,
      positives: codeRows.filter((r) => Number(r.label) === 1).length,
      negatives: codeRows.filter((r) => Number(r.label) === 0).length,
      strict: bCode.strict, triage: bCode.triage, tiers: tierBreakdown(codeRows),
    });

    const fullRows = vsmexRows.concat(benignRows);
    const bFull = bothRules(fullRows);
    sections.push({
      title: 'VsMex — FULL corpus (pessimistic bound)',
      note: 'Every Microsoft-removed extension counted as malicious, including the ~47% removed for impersonation, copyright, spam or at the owner\'s request. Those bundles typically contain no hostile code, so this matrix charges the detector for failures that are out of its scope. Reported for completeness.',
      n: fullRows.length,
      positives: fullRows.filter((r) => Number(r.label) === 1).length,
      negatives: fullRows.filter((r) => Number(r.label) === 0).length,
      strict: bFull.strict, triage: bFull.triage,
      tiers: tierBreakdown(fullRows), classes: classBreakdown(vsmexRows),
    });
  }

  if (allRows.length) {
    const b = bothRules(allRows);
    sections.push({
      title: 'Combined (all corpora pooled)',
      note: 'Both datasets together, every VsMex removal reason counted as malicious.',
      n: allRows.length,
      positives: allRows.filter((r) => Number(r.label) === 1).length,
      negatives: allRows.filter((r) => Number(r.label) === 0).length,
      strict: b.strict, triage: b.triage, tiers: tierBreakdown(allRows),
    });
  }

  const report = {
    generated_at: new Date().toISOString(),
    versions: { static: '3.0.0', sandbox: '3.0.0', orchestrator: '3.0.0' },
    options: {
      concurrency, limit: args.flags.limit || null,
      latest_only: !!args.flags['latest-only'], static_only: !!args.flags['static-only'],
      platform: args.flags.platform || 'win32',
    },
    datasets: datasets.map((d) => ({ dataset: d.dataset, group: d.group, analysed: d.analysed, stats: d.stats })),
    sections,
  };

  writeMetrics(outDir, report);
  const rc = writeRootCause(outDir, allRows);

  // ── Console summary ───────────────────────────────────────────────────────
  console.log('\n' + '═'.repeat(72));
  console.log('  RESULTS');
  console.log('═'.repeat(72));
  for (const s of sections) {
    console.log(`\n  ${s.title}   (n=${s.n})`);
    for (const [label, m] of [['STRICT', s.strict], ['TRIAGE', s.triage]]) {
      console.log(`    ${label.padEnd(7)} TP=${String(m.TP).padStart(4)} FP=${String(m.FP).padStart(4)} FN=${String(m.FN).padStart(4)} TN=${String(m.TN).padStart(4)}` +
                  `  P ${pct(m.precision).padStart(6)}  R ${pct(m.recall).padStart(6)}  F1 ${pct(m.f1).padStart(6)}  Acc ${pct(m.accuracy).padStart(6)}  MCC ${m.mcc.toFixed(3)}`);
    }
  }
  console.log('\n' + '─'.repeat(72));
  console.log(`  Residual FP ${rc.fps} · FN ${rc.fns} · errors ${rc.errors}`);
  console.log(`  METRICS.md    → ${path.join(outDir, 'METRICS.md')}`);
  console.log(`  ROOT-CAUSE.md → ${path.join(outDir, 'ROOT-CAUSE.md')}`);
  console.log(`  metrics.json  → ${path.join(outDir, 'metrics.json')}`);
  console.log('═'.repeat(72));
}

module.exports = { matrix, bothRules, diagnoseFN, diagnoseFP, writeMetrics, writeRootCause };

if (require.main === module) {
  main().catch((e) => { console.error('[BENCHMARK FATAL]', e && e.stack || e); process.exit(1); });
}
