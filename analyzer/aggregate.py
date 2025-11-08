#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import csv
import math
import argparse
from collections import defaultdict

CLASSES = ["EF", "AF31", "BE"]

def mean(values):
    return sum(values) / len(values) if values else float("nan")

def stddev(values):
    n = len(values)
    if n < 2:
        return float("nan")
    m = mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / (n - 1))

def ci95(values, t_factor=1.96):
    """
    95% CI przy założeniu normalności:
    mean ± t * (s / sqrt(n))

    Domyślnie t=1.96 (rozkład normalny).
    Jak będziesz miała dokładnie 10 przebiegów,
    możesz zmienić na t_factor=2.26 (Student dla df=9).
    """
    n = len(values)
    if n < 2:
        return (float("nan"), float("nan"))
    m = mean(values)
    s = stddev(values)
    se = s / math.sqrt(n)
    h = t_factor * se
    return (m - h, m + h)

def collect_from_csv(csv_path, data):
    """
    csv_path: ścieżka do baseline_summary_rx.csv
    data: słownik [klasa][metryka] -> lista wartości
    """
    with open(csv_path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            cls = row.get("class", "").strip()
            if cls not in CLASSES:
                continue

            # Każda metryka może być pusta, więc parsujemy ostrożnie
            thr_str = row.get("throughput_rx_Mbps", "").strip()
            jit_str = row.get("jitter_ms", "").strip()
            los_str = row.get("loss_pct", "").strip()

            if thr_str:
                try:
                    data[cls]["throughput"].append(float(thr_str))
                except ValueError:
                    pass
            if jit_str:
                try:
                    data[cls]["jitter"].append(float(jit_str))
                except ValueError:
                    pass
            if los_str:
                try:
                    data[cls]["loss"].append(float(los_str))
                except ValueError:
                    pass

def main():
    ap = argparse.ArgumentParser(
        description="Agregacja wielu baseline_summary_rx.csv + 95% CI."
    )
    ap.add_argument(
        "--runs-root",
        required=True,
        help="Katalog z wieloma biegami (podkatalogi z baseline_summary_rx.csv).",
    )
    ap.add_argument(
        "--out-csv",
        required=True,
        help="Ścieżka do zbiorczego pliku CSV z agregacją.",
    )
    ap.add_argument(
        "--t-factor",
        type=float,
        default=1.96,
        help="Kwantyl t dla 95%% CI (domyślnie 1.96). Np. ~2.26 dla n≈10 (Student).",
    )
    args = ap.parse_args()

    # Szukamy podkatalogów z baseline_summary_rx.csv
    run_dirs = []
    for name in sorted(os.listdir(args.runs_root)):
        d = os.path.join(args.runs_root, name)
        if not os.path.isdir(d):
            continue
        csv_path = os.path.join(d, "baseline_summary_rx.csv")
        if os.path.exists(csv_path):
            run_dirs.append(d)

    print(f"Znaleziono {len(run_dirs)} biegów z baseline_summary_rx.csv.")

    if not run_dirs:
        print("Brak plików do agregacji, sprawdź --runs-root.")
        return

    # Struktura danych: data[klasa]["throughput" | "jitter" | "loss"] -> [wartości]
    data = {
        cls: {
            "throughput": [],
            "jitter": [],
            "loss": [],
        } for cls in CLASSES
    }

    for d in run_dirs:
        csv_path = os.path.join(d, "baseline_summary_rx.csv")
        collect_from_csv(csv_path, data)

    # Zapis zbiorczego raportu
    with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "class",
            "n_throughput",
            "throughput_mean_Mbps",
            "throughput_ci95_low",
            "throughput_ci95_high",
            "n_jitter",
            "jitter_mean_ms",
            "jitter_ci95_low",
            "jitter_ci95_high",
            "n_loss",
            "loss_mean_pct",
            "loss_ci95_low",
            "loss_ci95_high",
        ])

        for cls in CLASSES:
            thr_vals = data[cls]["throughput"]
            jit_vals = data[cls]["jitter"]
            los_vals = data[cls]["loss"]

            thr_m = mean(thr_vals)
            thr_lo, thr_hi = ci95(thr_vals, t_factor=args.t_factor)

            jit_m = mean(jit_vals)
            jit_lo, jit_hi = ci95(jit_vals, t_factor=args.t_factor)

            los_m = mean(los_vals)
            los_lo, los_hi = ci95(los_vals, t_factor=args.t_factor)

            w.writerow([
                cls,
                len(thr_vals),
                f"{thr_m:.3f}",
                f"{thr_lo:.3f}",
                f"{thr_hi:.3f}",
                len(jit_vals),
                f"{jit_m:.3f}",
                f"{jit_lo:.3f}",
                f"{jit_hi:.3f}",
                len(los_vals),
                f"{los_m:.3f}",
                f"{los_lo:.3f}",
                f"{los_hi:.3f}",
            ])

    print(f"Gotowe, zapisano zbiorczy raport do: {args.out_csv}")

if __name__ == "__main__":
    main()
