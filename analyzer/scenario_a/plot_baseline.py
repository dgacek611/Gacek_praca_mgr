#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, argparse, math, csv
import matplotlib.pyplot as plt

# ========= Wspólne ustawienia wyglądu (spójność A/B/C) =========
TITLE_FONTSIZE = 16
TITLE_WEIGHT   = "bold"
LABEL_FONTSIZE = 12
LABEL_WEIGHT   = "bold"
TICK_FONTSIZE  = 11
ANNOT_FONTSIZE = 10

ORDER = ["BE", "AF31", "EF"]  # stała kolejność klas na wszystkich wykresach

def _apply_axes_style(ax, title: str, ylabel: str, ylim=None):
    ax.set_title(title, fontsize=TITLE_FONTSIZE, fontweight=TITLE_WEIGHT)
    ax.set_ylabel(ylabel, fontsize=LABEL_FONTSIZE, fontweight=LABEL_WEIGHT)
    ax.set_xlabel("Klasa", fontsize=LABEL_FONTSIZE, fontweight=LABEL_WEIGHT)
    ax.tick_params(axis="both", labelsize=TICK_FONTSIZE)
    if ylim is not None and len(ylim) == 2:
        ax.set_ylim(ylim[0], ylim[1])

def _annotate_bars(ax):
    for p in ax.patches:
        h = p.get_height()
        if h == h:  # not NaN
            ax.annotate(f"{h:.2f}", (p.get_x() + p.get_width()/2., h),
                        ha="center", va="bottom", xytext=(0, 3),
                        textcoords="offset points", fontsize=ANNOT_FONTSIZE)

def _bar_plot(labels, values, title, ylabel, out_png, ylim=None, yerr=None):
    fig = plt.figure()
    x = range(len(labels))
    # error bary z 95% CI
    plt.bar(x, values, tick_label=labels, yerr=yerr, capsize=5 if yerr is not None else 0)
    ax = plt.gca()
    _apply_axes_style(ax, title, ylabel, ylim=ylim)
    _annotate_bars(ax)
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close(fig)

def _mean_ci95(values):
    """
    Zwraca (mean, half_width_95CI) dla listy wartości.
    Ignoruje NaN / puste teksty.
    """
    cleaned = []
    for v in values:
        if isinstance(v, (int, float)):
            if not math.isnan(v):
                cleaned.append(float(v))
        else:
            # np. pusty string z CSV
            try:
                fv = float(v)
                if not math.isnan(fv):
                    cleaned.append(fv)
            except Exception:
                continue

    if not cleaned:
        return float("nan"), float("nan")

    n = len(cleaned)
    mean = sum(cleaned) / n
    if n > 1:
        var = sum((x - mean) ** 2 for x in cleaned) / (n - 1)
        std = math.sqrt(var)
        z = 1.96  # przybliżenie dla 95% (normalny)
        half_width = z * std / math.sqrt(n)
    else:
        std = float("nan")
        half_width = float("nan")

    return mean, half_width

def _load_metrics_from_csv(csv_path):
    """
    Czyta all_runs_summary_rx.csv i liczy średnie + 95% CI
    dla throughput / jitter / loss per klasa (BE, AF31, EF).
    Zwraca dict:
      { 'BE':  {'thr_mean':..., 'thr_ci':..., 'jit_mean':..., ...},
        'AF31': {...},
        'EF':   {...} }
    """
    # zbierz wartości z wszystkich runów
    data = {cls: {"thr": [], "jit": [], "loss": []} for cls in ORDER}

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cls = row.get("class")
            if cls not in data:
                continue
            # throughput
            t = row.get("throughput_rx_Mbps", "")
            j = row.get("jitter_ms", "")
            l = row.get("loss_pct", "")

            for key, raw in (("thr", t), ("jit", j), ("loss", l)):
                try:
                    v = float(raw)
                except Exception:
                    v = float("nan")
                data[cls][key].append(v)

    # policz średnie i CI
    stats = {}
    for cls in ORDER:
        thr_mean, thr_ci = _mean_ci95(data[cls]["thr"])
        jit_mean, jit_ci = _mean_ci95(data[cls]["jit"])
        loss_mean, loss_ci = _mean_ci95(data[cls]["loss"])
        stats[cls] = {
            "throughput_mean": thr_mean,
            "throughput_ci": thr_ci,
            "jitter_mean": jit_mean,
            "jitter_ci": jit_ci,
            "loss_mean": loss_mean,
            "loss_ci": loss_ci,
        }
    return stats

def main():
    ap = argparse.ArgumentParser(description="Plot Scenario A (Baseline) EF/AF/BE stats (średnia ± 95% CI)")
    ap.add_argument("--csv", required=True, help="Ścieżka do all_runs_summary_rx.csv (z wielu runów scenariusza A)")
    ap.add_argument("--out-prefix", default=".", help="Prefiks ścieżki wyjściowej (katalog)")
    # Jednolite skale
    ap.add_argument("--ylim-throughput", nargs=2, type=float, default=[0.0, 60.0], metavar=("YMIN","YMAX"))
    ap.add_argument("--ylim-loss",       nargs=2, type=float, default=[0.0, 100.0], metavar=("YMIN","YMAX"))
    ap.add_argument("--ylim-jitter",     nargs=2, type=float, default=[0.0, 10.0],  metavar=("YMIN","YMAX"))
    args = ap.parse_args()

    stats = _load_metrics_from_csv(args.csv)
    labels = list(ORDER)

    thr_means = [stats[k]["throughput_mean"] for k in labels]
    thr_cis   = [stats[k]["throughput_ci"]   for k in labels]

    loss_means = [stats[k]["loss_mean"] for k in labels]
    loss_cis   = [stats[k]["loss_ci"]   for k in labels]

    jit_means = [stats[k]["jitter_mean"] for k in labels]
    jit_cis   = [stats[k]["jitter_ci"]   for k in labels]

    out_dir = args.out_prefix
    os.makedirs(out_dir, exist_ok=True)

    _bar_plot(labels, thr_means,
              "Baseline (Scenario A)", "Throughput (RX) [Mb/s]",
              os.path.join(out_dir, "a_throughput_rx_ci.png"),
              ylim=tuple(args.ylim_throughput),
              yerr=thr_cis)

    _bar_plot(labels, loss_means,
              "Baseline (Scenario A)", "Packet loss [%]",
              os.path.join(out_dir, "a_loss_rx_ci.png"),
              ylim=tuple(args.ylim_loss),
              yerr=loss_cis)

    _bar_plot(labels, jit_means,
              "Baseline (Scenario A)", "Jitter [ms]",
              os.path.join(out_dir, "a_jitter_rx_ci.png"),
              ylim=tuple(args.ylim_jitter),
              yerr=jit_cis)

    print("OK: zapisano A-wykresy (średnia ± 95% CI) do", out_dir)

if __name__ == "__main__":
    main()
