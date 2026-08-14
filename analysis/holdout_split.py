#!/usr/bin/env python3
"""
Track B: freeze a held-out validation partition.

Detection rules/thresholds in VEXGuard were tuned iteratively against the
same DataDog corpus now used to report headline metrics (see
docs/EVALUATION-METHODOLOGY.md). This script does not fix that retroactively
— it can't, the tuning already happened — but it draws a line for the
future: a stratified ~25% sample of each corpus, frozen now with a fixed
seed, that must never be used to tune a rule or threshold again. Any future
rule change is only allowed to cite its effect on this held-out partition
as evidence of generalization.

Reads only the existing results-*.csv files (ground truth + tier are
already recorded there); does not touch the Node.js engine or re-run
anything.

Usage:
    .venv/Scripts/python analysis/holdout_split.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "vexguard-results"
OUT_PATH = Path(__file__).resolve().parent / "holdout_ids.json"

HOLDOUT_FRACTION = 0.25
RNG_SEED = 20260811  # fixed — must never change once holdout_ids.json is committed

CSV_FILES = [
    RESULTS_DIR / "results-datadog-malicious.csv",
    RESULTS_DIR / "results-datadog-benign.csv",
    RESULTS_DIR / "results-vsmex.csv",
]


def main():
    if OUT_PATH.exists():
        raise SystemExit(
            f"{OUT_PATH} already exists. The holdout partition is frozen by design — "
            "delete it manually first if you really intend to redraw it (this "
            "invalidates any past claim of 'validated on the holdout')."
        )

    frames = []
    for path in CSV_FILES:
        if not path.exists():
            print(f"  (skip {path.name}: not found)")
            continue
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        frames.append(df)
    all_df = pd.concat(frames, ignore_index=True)
    all_df = all_df[all_df["final_verdict"] != "ERROR"]

    holdout_parts = []
    print(f"{'dataset':<20} {'tier':<10} {'label':<6} {'n':>6} {'holdout':>8}")
    for (dataset, tier, label), grp in all_df.groupby(["dataset", "tier", "label"], sort=True):
        sample = grp.sample(frac=HOLDOUT_FRACTION, random_state=RNG_SEED)
        holdout_parts.append(sample)
        print(f"{dataset:<20} {tier:<10} {label:<6} {len(grp):>6} {len(sample):>8}")

    holdout_df = pd.concat(holdout_parts, ignore_index=True)
    records = holdout_df[["dataset", "id", "version", "label", "tier"]].to_dict("records")

    out = {
        "generated_at_seed": RNG_SEED,
        "fraction": HOLDOUT_FRACTION,
        "policy": (
            "This partition must never be used to tune detection rules or "
            "thresholds. It is the only population future rule changes may "
            "cite as evidence of generalization. See docs/EVALUATION-METHODOLOGY.md."
        ),
        "n_total": len(records),
        "samples": records,
    }
    OUT_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {OUT_PATH} — {len(records)} samples frozen as holdout "
          f"({len(records) / len(all_df) * 100:.1f}% of {len(all_df)} total).")


if __name__ == "__main__":
    main()
