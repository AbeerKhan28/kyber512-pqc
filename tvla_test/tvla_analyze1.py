#!/usr/bin/env python3
"""
tvla_analyze.py

Analyzes a "class,cycles" trace log captured from tvla_harness.c
(via USB serial -> logged to a file, e.g. with `picocom -b 115200 | tee trace.csv`
or a plain terminal capture).

Usage:
    python3 tvla_analyze.py trace.csv [--batches 5]

What it does:
  1. Parses the log, splits into Class A ("fixed") and Class B ("random").
  2. Runs a Welch's t-test (unequal variance) over the full dataset --
     the standard first-order TVLA statistic.
  3. Flags |t| >= 4.5 as a detected leak (the conventional TVLA threshold,
     corresponding to a false-positive rate of ~1e-5 for a single test).
  4. Splits the trace into N independent sequential batches and repeats
     the test on each -- this is the "repeated tests" the reviewer asked
     for. A real leak should show up consistently across batches; a
     borderline |t|~4.5 result that only appears in one batch out of
     several is much weaker evidence than one that appears in all of them.
  5. Prints summary stats (mean/stdev/n per class) and saves a histogram
     comparison plot.
"""

import sys
import argparse
import csv
import statistics
import math

try:
    from scipy import stats as spstats
    HAVE_SCIPY = True
except ImportError:
    HAVE_SCIPY = False


def welch_t_test(a, b):
    """Welch's t-test, returns (t_statistic, dof). Implemented from
    scratch so this works even without scipy; uses scipy for the
    p-value if available."""
    n_a, n_b = len(a), len(b)
    mean_a, mean_b = statistics.fmean(a), statistics.fmean(b)
    var_a, var_b = statistics.variance(a, mean_a), statistics.variance(b, mean_b)

    se2 = var_a / n_a + var_b / n_b
    t = (mean_a - mean_b) / math.sqrt(se2)

    # Welch-Satterthwaite degrees of freedom
    dof_num = se2 ** 2
    dof_den = (var_a / n_a) ** 2 / (n_a - 1) + (var_b / n_b) ** 2 / (n_b - 1)
    dof = dof_num / dof_den if dof_den > 0 else float("nan")

    return t, dof, mean_a, mean_b, var_a, var_b


def report(label, a, b):
    t, dof, mean_a, mean_b, var_a, var_b = welch_t_test(a, b)
    verdict = "LEAK DETECTED" if abs(t) >= 4.5 else "no leak detected"

    print(f"--- {label} ---")
    print(f"  Class A (fixed):  n={len(a):>7}  mean={mean_a:12.3f} cycles  stdev={math.sqrt(var_a):10.3f}")
    print(f"  Class B (random): n={len(b):>7}  mean={mean_b:12.3f} cycles  stdev={math.sqrt(var_b):10.3f}")
    print(f"  Welch t = {t:+.3f}  (dof={dof:.1f})  threshold=|t|>=4.5  ->  {verdict}")
    if HAVE_SCIPY:
        p = spstats.t.sf(abs(t), dof) * 2
        print(f"  two-sided p-value = {p:.3e}")
    print()
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--batches", type=int, default=5,
                     help="number of independent sequential batches for repeated testing (default 5)")
    ap.add_argument("--plot", action="store_true", help="save a histogram comparison plot")
    args = ap.parse_args()

    SEGMENT_NAMES = ["seg_unpack", "seg_msgrecover", "seg_keyderive", "seg_reencrypt", "seg_cmov", "total"]

    # rows_by_segment[name] -> list of (class, value) in file order
    rows_by_segment = {name: [] for name in SEGMENT_NAMES}

    with open(args.logfile, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if row[0].strip() == "class":  # header line
                continue
            if len(row) != 7:
                continue  # tolerate stray/old-format lines
            cls = row[0].strip()
            if cls not in ("A", "B"):
                continue
            try:
                vals = [int(x) for x in row[1:]]
            except ValueError:
                continue
            for name, v in zip(SEGMENT_NAMES, vals):
                rows_by_segment[name].append((cls, v))

    if not rows_by_segment["total"]:
        print("No valid rows parsed -- check the log format "
              "(expect 'class,seg_unpack,seg_msgrecover,seg_keyderive,seg_reencrypt,seg_cmov,total').")
        sys.exit(1)

    order = rows_by_segment["total"]  # for batch splitting / interleave order
    n_total_rows = len(order)
    print(f"Parsed {n_total_rows} trials from {args.logfile} "
          f"({sum(1 for c, _ in order if c == 'A')} Class-A, "
          f"{sum(1 for c, _ in order if c == 'B')} Class-B)\n")

    # Run full-dataset TVLA independently on every segment, so we can see
    # WHICH segment carries the leak rather than just the total.
    print("=" * 70)
    print("PER-SEGMENT BISECTION (full dataset)")
    print("=" * 70)
    segment_t = {}
    for name in SEGMENT_NAMES:
        a = [v for c, v in rows_by_segment[name] if c == "A"]
        b = [v for c, v in rows_by_segment[name] if c == "B"]
        t = report(name, a, b)
        segment_t[name] = t

    print("=" * 70)
    print("BISECTION SUMMARY")
    print("=" * 70)
    for name in SEGMENT_NAMES:
        flag = "  <-- LEAK" if abs(segment_t[name]) >= 4.5 else ""
        print(f"  {name:18s}  t = {segment_t[name]:+9.3f}{flag}")
    print()

    # Below: repeated-batch analysis on the TOTAL column only (the
    # per-segment full-dataset numbers above already localize the leak;
    # batches are for confirming the total-column leak is reproducible,
    # matching the reviewer's "repeated tests" requirement).
    a_all = [v for c, v in order if c == "A"]
    b_all = [v for c, v in order if c == "B"]

    # Repeated tests: split the interleaved sequence into N sequential
    # batches, each internally still a mix of A/B, and test each batch
    # independently. This is what catches a leak that's real-but-marginal
    # vs. one that was a fluke of a single large run.
    n = len(order)
    batch_size = n // args.batches
    if batch_size < 200:
        print(f"(Skipping batch split -- only {n} total traces, too few per batch for {args.batches} batches.)")
        return

    t_values = []
    for i in range(args.batches):
        chunk = order[i * batch_size: (i + 1) * batch_size] if i < args.batches - 1 else order[i * batch_size:]
        a = [c for lbl, c in chunk if lbl == "A"]
        b = [c for lbl, c in chunk if lbl == "B"]
        if len(a) < 30 or len(b) < 30:
            continue
        t = report(f"Batch {i+1}/{args.batches}", a, b)
        t_values.append(t)

    n_leak = sum(1 for t in t_values if abs(t) >= 4.5)
    print(f"=== Summary across {len(t_values)} batches: {n_leak} flagged |t|>=4.5 ===")
    if n_leak == 0:
        print("No leak detected in any batch. Consistent with constant-time behavior for this test.")
    elif n_leak == len(t_values):
        print("Leak detected consistently in EVERY batch -- strong evidence of a real, reproducible leak.")
    else:
        print("Leak detected in SOME but not all batches -- inconclusive; investigate further "
              "(more traces, check for environmental confounds, or a marginal/intermittent leak).")

    if args.plot:
        try:
            import matplotlib.pyplot as plt
            plt.hist(a_all, bins=100, alpha=0.5, label="Class A (fixed)")
            plt.hist(b_all, bins=100, alpha=0.5, label="Class B (random)")
            plt.xlabel("Cycles")
            plt.ylabel("Count")
            plt.legend()
            plt.title("TVLA: decapsulate() cycle distributions")
            out = args.logfile + ".png"
            plt.savefig(out, dpi=150)
            print(f"\nSaved histogram to {out}")
        except ImportError:
            print("\n(matplotlib not available -- skipping plot)")


if __name__ == "__main__":
    main()
