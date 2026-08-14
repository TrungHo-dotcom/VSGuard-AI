#!/usr/bin/env python3
"""
Track A statistical supplement for the VEXGuard evaluation.

Reads the engine's own already-computed results under vexguard-results/
(results-*.jsonl) and adds statistical rigor the headline report doesn't
have: Wilson confidence intervals, bootstrap CIs for F1/MCC/balanced
accuracy, ROC-AUC/PR-AUC across the full score range, an ablation of
static-only vs dynamic-only vs combined, and per-technique recall.

This script does not re-run the engine, does not call any VEXGuard module,
and does not alter any verdict. It is read-only w.r.t. the Node.js package.

Usage:
    .venv/Scripts/python analysis/statistical_analysis.py
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from statsmodels.stats.proportion import proportion_confint

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "vexguard-results"
JSONL_FILES = {
    "datadog-malicious": RESULTS_DIR / "results-datadog-malicious.jsonl",
    "datadog-benign": RESULTS_DIR / "results-datadog-benign.jsonl",
    "vsmex": RESULTS_DIR / "results-vsmex.jsonl",
}
# CSV fallback for any dataset whose .jsonl wasn't generated/kept (e.g. the
# benign control set here only has a .csv on disk). CSV lacks `families`,
# `corroborated` and `duration_ms`; those default to empty/None for such
# rows, which only matters for label==1 analyses — the benign set is
# label==0 throughout, so this fallback doesn't weaken any positive-side
# statistic.
CSV_FILES = {
    "datadog-malicious": RESULTS_DIR / "results-datadog-malicious.csv",
    "datadog-benign": RESULTS_DIR / "results-datadog-benign.csv",
    "vsmex": RESULTS_DIR / "results-vsmex.csv",
}

BOOTSTRAP_N = 2000
RNG_SEED = 20260811  # fixed for reproducibility; do not vary between runs


# ─────────────────────────────────────────────────────────────────────────────
#  Load
# ─────────────────────────────────────────────────────────────────────────────

def _verdict_flags(verdict_str: str, score: float):
    """CSV rows only store the verdict string + score, not is_malicious/is_flagged
    flags directly. Derive them the same way the engine's rank does: MALICIOUS
    => both flags set, SUSPICIOUS => flagged only, BENIGN => neither."""
    v = (verdict_str or "BENIGN").upper()
    is_malicious = 1 if v == "MALICIOUS" else 0
    is_flagged = 1 if v in ("MALICIOUS", "SUSPICIOUS") else 0
    return is_malicious, is_flagged


def _load_jsonl(path: Path, default_dataset: str) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            meta = r.get("meta") or {}
            verdict = r.get("verdict") or {}
            static = r.get("static") or {}
            dynamic = r.get("dynamic") or {}
            intel = r.get("intel") or {}
            # NOTE: the exported `verdict` object in results-*.jsonl carries
            # `final` (string) + `is_malicious` but does NOT include
            # `is_flagged` (only the CSV export's `final_is_flagged` column
            # does). Derive is_flagged/is_malicious from the verdict string
            # itself so JSONL- and CSV-sourced rows agree — relying on the
            # absent JSONL field silently produced TRIAGE TP=0 everywhere.
            final_mal, final_flag = _verdict_flags(verdict.get("final"), verdict.get("score", 0))
            static_mal, static_flag = _verdict_flags(static.get("verdict"), static.get("score", 0))
            dynamic_mal, dynamic_flag = _verdict_flags(dynamic.get("verdict"), dynamic.get("score", 0))
            records.append({
                "dataset": meta.get("dataset", default_dataset),
                "id": meta.get("id"),
                "version": meta.get("version"),
                "label": int(meta.get("label", 0) or 0),
                "tier": meta.get("tier", ""),
                "final_verdict": verdict.get("final"),
                "is_malicious": final_mal,
                "is_flagged": final_flag,
                "score": float(verdict.get("score", 0) or 0),
                "decided_by": verdict.get("decided_by", ""),
                "corroborated": tuple(verdict.get("corroborated", []) or []),
                "static_verdict": static.get("verdict", "BENIGN"),
                "static_is_malicious": static_mal,
                "static_is_flagged": static_flag,
                "dynamic_verdict": dynamic.get("verdict", "BENIGN"),
                "dynamic_is_malicious": dynamic_mal,
                "dynamic_is_flagged": dynamic_flag,
                "families": tuple(intel.get("families", []) or []),
                "duration_ms": r.get("duration_ms"),  # absent until Track B re-run
                "timed_out": bool(r.get("timed_out", False)),
            })
    return records


def _load_csv(path: Path, default_dataset: str) -> list[dict]:
    records = []
    cdf = pd.read_csv(path, dtype=str, keep_default_na=False)
    for _, row in cdf.iterrows():
        score = float(row.get("score") or 0)
        static_score = float(row.get("static_score") or 0)
        dynamic_score = float(row.get("dynamic_score") or 0)
        static_mal, static_flag = _verdict_flags(row.get("static_verdict"), static_score)
        dynamic_mal, dynamic_flag = _verdict_flags(row.get("dynamic_verdict"), dynamic_score)
        final_mal, final_flag = _verdict_flags(row.get("final_verdict"), score)
        records.append({
            "dataset": row.get("dataset") or default_dataset,
            "id": row.get("id"),
            "version": row.get("version"),
            "label": int(row.get("label") or 0),
            "tier": row.get("tier") or "",
            "final_verdict": row.get("final_verdict"),
            "is_malicious": int(row.get("final_is_malicious") or final_mal),
            "is_flagged": int(row.get("final_is_flagged") or final_flag),
            "score": score,
            "decided_by": row.get("decided_by") or "",
            "corroborated": tuple(),  # not present in CSV; only used on label==1 breakdowns
            "static_verdict": row.get("static_verdict") or "BENIGN",
            "static_is_malicious": static_mal,
            "static_is_flagged": static_flag,
            "dynamic_verdict": row.get("dynamic_verdict") or "BENIGN",
            "dynamic_is_malicious": dynamic_mal,
            "dynamic_is_flagged": dynamic_flag,
            "families": tuple(),  # not present in CSV; only used on label==1 breakdowns
            "duration_ms": None,
            "timed_out": (row.get("timed_out") or "0") in ("1", "True", "true"),
        })
    return records


def load_rows() -> pd.DataFrame:
    records = []
    for default_dataset, jsonl_path in JSONL_FILES.items():
        if jsonl_path.exists():
            rows = _load_jsonl(jsonl_path, default_dataset)
            print(f"  {jsonl_path.name}: {len(rows)} rows (jsonl)")
            records.extend(rows)
            continue
        csv_path = CSV_FILES.get(default_dataset)
        if csv_path and csv_path.exists():
            rows = _load_csv(csv_path, default_dataset)
            print(f"  {jsonl_path.name} not found — fell back to {csv_path.name}: {len(rows)} rows (families/corroborated/duration unavailable for these)")
            records.extend(rows)
            continue
        print(f"  (skip {default_dataset}: neither jsonl nor csv found)")
    df = pd.DataFrame.from_records(records)
    errors = df[df["final_verdict"] == "ERROR"]
    if len(errors):
        print(f"  NOTE: {len(errors)} ERROR row(s) excluded from all confusion-matrix metrics below.")
    return df[df["final_verdict"] != "ERROR"].reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Section definitions — mirror vexguard-results/metrics.json exactly, so
#  point estimates computed here can be cross-checked against that file.
# ─────────────────────────────────────────────────────────────────────────────

def _datadog(df):
    return df["dataset"].isin(["datadog-malicious", "datadog-benign"])


def _vsmex_code(df):
    return ((df["dataset"] == "vsmex") & (df["tier"] == "code")) | (df["dataset"] == "datadog-benign")


def _vsmex_full(df):
    return (df["dataset"] == "vsmex") | (df["dataset"] == "datadog-benign")


def _combined(df):
    return pd.Series(True, index=df.index)


SECTIONS = [
    ("DataDog corpus", _datadog),
    ("VsMex code-level subset (primary)", _vsmex_code),
    ("VsMex full corpus (pessimistic bound)", _vsmex_full),
    ("Combined (all corpora pooled)", _combined),
]

RULES = {"STRICT": "is_malicious", "TRIAGE": "is_flagged"}


# ─────────────────────────────────────────────────────────────────────────────
#  Statistics
# ─────────────────────────────────────────────────────────────────────────────

def confusion(y: np.ndarray, p: np.ndarray):
    tp = int(((y == 1) & (p == 1)).sum())
    fp = int(((y == 0) & (p == 1)).sum())
    fn = int(((y == 1) & (p == 0)).sum())
    tn = int(((y == 0) & (p == 0)).sum())
    return tp, fp, fn, tn


def wilson(k: int, n: int):
    """Point estimate + 95% Wilson score interval for a binomial proportion."""
    if n == 0:
        return {"point": None, "lo": None, "hi": None, "n": 0}
    point = k / n
    lo, hi = proportion_confint(k, n, alpha=0.05, method="wilson")
    return {"point": point, "lo": lo, "hi": hi, "n": n}


def bootstrap_ci(y: np.ndarray, p: np.ndarray, n_boot=BOOTSTRAP_N, seed=RNG_SEED):
    """Case-resampling bootstrap CI for F1, MCC, balanced accuracy."""
    rng = np.random.default_rng(seed)
    n = len(y)
    f1s, mccs, bas = [], [], []
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        yb, pb = y[idx], p[idx]
        tp, fp, fn, tn = confusion(yb, pb)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0
        spec = tn / (tn + fp) if (tn + fp) else 0.0
        ba = (rec + spec) / 2
        f1s.append(f1)
        mccs.append(mcc)
        bas.append(ba)

    def summarize(arr):
        arr = np.asarray(arr)
        return {"mean": float(arr.mean()), "lo": float(np.percentile(arr, 2.5)), "hi": float(np.percentile(arr, 97.5))}

    return {"f1": summarize(f1s), "mcc": summarize(mccs), "balanced_accuracy": summarize(bas)}


def section_rule_stats(df: pd.DataFrame, pred_col: str) -> dict:
    y = df["label"].to_numpy()
    p = df[pred_col].to_numpy()
    tp, fp, fn, tn = confusion(y, p)
    out = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": len(df),
        "precision": wilson(tp, tp + fp),
        "recall": wilson(tp, tp + fn),
        "specificity": wilson(tn, tn + fp),
    }
    out["bootstrap"] = bootstrap_ci(y, p)
    return out


def auc_stats(df: pd.DataFrame):
    y = df["label"].to_numpy()
    s = df["score"].to_numpy()
    if len(np.unique(y)) < 2:
        return None
    return {
        "roc_auc": float(roc_auc_score(y, s)),
        "pr_auc": float(average_precision_score(y, s)),
    }


def ablation_stats(df: pd.DataFrame):
    y = df["label"].to_numpy()
    out = {}
    for name, col in [("static_only", "static_is_malicious"), ("dynamic_only", "dynamic_is_malicious"), ("combined", "is_malicious")]:
        p = df[col].to_numpy()
        tp, fp, fn, tn = confusion(y, p)
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn) if (tp + fn) else None
        out[name] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec}

    tp_rows = df[(df["label"] == 1) & (df["is_malicious"] == 1)]
    n_tp = len(tp_rows)
    n_corrob = int((tp_rows["decided_by"] == "corroboration").sum())
    out["corroboration_dependency"] = {
        "strict_true_positives": n_tp,
        "decided_by_corroboration": n_corrob,
        "fraction": (n_corrob / n_tp) if n_tp else None,
    }
    return out


def family_recall(df: pd.DataFrame):
    positives = df[df["label"] == 1]
    exploded = positives.explode("families")
    exploded["families"] = exploded["families"].fillna("(uncategorised)")
    grp = exploded.groupby("families").agg(
        n=("label", "size"),
        caught=("is_malicious", "sum"),
    )
    grp["recall"] = grp["caught"] / grp["n"]
    grp = grp.sort_values("n", ascending=False)
    return grp.reset_index().to_dict("records")


def operational_stats(df: pd.DataFrame):
    if df["duration_ms"].isna().all():
        return None
    d = df["duration_ms"].dropna().astype(float)
    return {
        "n_with_timing": int(len(d)),
        "median_ms": float(d.median()),
        "p95_ms": float(d.quantile(0.95)),
        "max_ms": float(d.max()),
        "timeout_rate": float(df["timed_out"].mean()),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Report rendering
# ─────────────────────────────────────────────────────────────────────────────

def pct(x, digits=1):
    return "—" if x is None else f"{x * 100:.{digits}f}%"


def fmt_ci(d, digits=1):
    if d.get("point") is None:
        return "—"
    return f"{pct(d['point'], digits)} (95% CI {pct(d['lo'], digits)}–{pct(d['hi'], digits)}, n={d['n']})"


def fmt_boot(d, digits=3):
    return f"{d['mean']:.{digits}f} (95% CI {d['lo']:.{digits}f}–{d['hi']:.{digits}f})"


def build_report(df: pd.DataFrame) -> tuple[str, dict]:
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = []
    lines.append("# VEXGuard — Statistical Supplement")
    lines.append("")
    lines.append("> **Supplementary analysis — not part of the graded engine.**")
    lines.append("> Computed on top of the existing `vexguard-results/results-*.jsonl` files.")
    lines.append("> Does not re-run the engine and does not alter any verdict.")
    lines.append(f"> Generated: {generated_at}")
    lines.append("")
    lines.append(
        "This supplement adds confidence intervals, threshold-independent "
        "discriminative power, an ablation of the static/dynamic/corroboration "
        "contributions, and per-technique recall to the point estimates already "
        "reported in `METRICS.md`. See `docs/EVALUATION-METHODOLOGY.md` for the "
        "held-out validation policy this supplement does **not** substitute for: "
        "every number below is still measured on the corpus used to tune the "
        "detection rules."
    )
    lines.append("")

    json_out = {"generated_at": generated_at, "sections": []}

    for name, pred in SECTIONS:
        sub = df[pred(df)]
        lines.append(f"## {name}  (n = {len(sub)})")
        lines.append("")
        section_json = {"name": name, "n": len(sub), "rules": {}}

        for rule_name, col in RULES.items():
            stats = section_rule_stats(sub, col)
            section_json["rules"][rule_name] = stats
            lines.append(f"### {rule_name}")
            lines.append("")
            lines.append(f"- TP={stats['tp']} FP={stats['fp']} FN={stats['fn']} TN={stats['tn']}")
            lines.append(f"- Precision: {fmt_ci(stats['precision'])}")
            lines.append(f"- Recall: {fmt_ci(stats['recall'])}")
            lines.append(f"- Specificity (TNR): {fmt_ci(stats['specificity'])}")
            b = stats["bootstrap"]
            lines.append(f"- F1 (bootstrap, {BOOTSTRAP_N} resamples): {fmt_boot(b['f1'])}")
            lines.append(f"- MCC (bootstrap): {fmt_boot(b['mcc'])}")
            lines.append(f"- Balanced accuracy (bootstrap): {fmt_boot(b['balanced_accuracy'])}")
            lines.append("")

        auc = auc_stats(sub)
        section_json["auc"] = auc
        if auc:
            lines.append(
                f"**ROC-AUC (raw score vs. label): {auc['roc_auc']:.3f} · "
                f"PR-AUC: {auc['pr_auc']:.3f}**  "
                "— threshold-independent view; note the cross-modality "
                "corroboration rule can escalate a verdict to MALICIOUS without "
                "raising `score`, so a handful of points are not explained by "
                "score alone."
            )
        else:
            lines.append("ROC/PR-AUC: not computable (single class in this section).")
        lines.append("")

        ab = ablation_stats(sub)
        section_json["ablation"] = ab
        lines.append("**Ablation (STRICT confusion matrix per modality):**")
        lines.append("")
        lines.append("| Modality | TP | FP | FN | TN | Precision | Recall |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for mod in ["static_only", "dynamic_only", "combined"]:
            m = ab[mod]
            lines.append(f"| {mod} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {pct(m['precision'])} | {pct(m['recall'])} |")
        lines.append("")
        cd = ab["corroboration_dependency"]
        lines.append(
            f"Of {cd['strict_true_positives']} STRICT true positives, "
            f"{cd['decided_by_corroboration']} ({pct(cd['fraction'])}) were escalated "
            "by the cross-modality corroboration rule specifically — i.e. would "
            "not have reached MALICIOUS on either modality's score alone."
        )
        lines.append("")

        fam = family_recall(sub)
        section_json["family_recall"] = fam
        if fam:
            lines.append("**Recall by technique family (`intel.families`, ground-truth positives only):**")
            lines.append("")
            lines.append("| Family | n | Caught | Recall |")
            lines.append("|---|---:|---:|---:|")
            for row in fam:
                lines.append(f"| {row['families']} | {row['n']} | {row['caught']} | {pct(row['recall'])} |")
            lines.append("")

        json_out["sections"].append(section_json)

    op = operational_stats(df)
    json_out["operational"] = op
    lines.append("## Operational metrics")
    lines.append("")
    if op:
        lines.append(f"- Samples with timing data: {op['n_with_timing']}")
        lines.append(f"- Median analysis duration: {op['median_ms']:.0f} ms")
        lines.append(f"- p95 analysis duration: {op['p95_ms']:.0f} ms")
        lines.append(f"- Max analysis duration: {op['max_ms']:.0f} ms")
        lines.append(f"- Timeout rate: {pct(op['timeout_rate'])}")
    else:
        lines.append(
            "Not available — the current `vexguard-results/*.jsonl` files predate "
            "the `duration_ms` timing instrumentation. Re-run "
            "`node benchmark.js --datasets all --concurrency 8` after that change "
            "lands to populate this section."
        )
    lines.append("")

    return "\n".join(lines), json_out


def main():
    print("Loading rows from vexguard-results/results-*.jsonl ...")
    df = load_rows()
    print(f"  loaded {len(df)} rows across {df['dataset'].nunique()} dataset file(s)")

    report_md, report_json = build_report(df)

    md_path = RESULTS_DIR / "STATISTICAL-SUPPLEMENT.md"
    json_path = RESULTS_DIR / "statistical_supplement.json"
    md_path.write_text(report_md, encoding="utf-8")
    json_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")
    print(f"Wrote {md_path}")
    print(f"Wrote {json_path}")


if __name__ == "__main__":
    main()
