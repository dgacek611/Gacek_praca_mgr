#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, argparse
import pandas as pd
import matplotlib.pyplot as plt

def read_iperf_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_iperf(stream):
    # Zwraca dict: throughput_rx_Mbps, jitter_ms, loss_pct (sum_received → sum → sum_sent)
    try:
        end = stream.get("end", {})
        s = end.get("sum_received") or end.get("sum") or end.get("sum_sent")
        if not s:
            return {"throughput_rx_Mbps": float("nan"), "jitter_ms": float("nan"), "loss_pct": float("nan")}
        tput = s.get("bits_per_second", float("nan")) / 1e6
        jitter = s.get("jitter_ms", end.get("sum", {}).get("jitter_ms", float("nan")))
        lost = s.get("lost_packets", end.get("sum", {}).get("lost_packets", 0))
        sent = s.get("packets", end.get("sum", {}).get("packets", 0))
        loss = s.get("lost_percent") if "lost_percent" in s else ((100.0 * lost / sent) if sent else float("nan"))
        return {"throughput_rx_Mbps": tput, "jitter_ms": jitter, "loss_pct": loss}
    except Exception:
        return {"throughput_rx_Mbps": float("nan"), "jitter_ms": float("nan"), "loss_pct": float("nan")}

def load_metrics(run_dir):
    clients = os.path.join(run_dir, "clients")
    files = {
        "EF": os.path.join(clients, "ef.json"),
        "AF31": os.path.join(clients, "af31.json"),
        "BE": os.path.join(clients, "be.json"),
    }
    rows = []
    for klass, p in files.items():
        if os.path.exists(p):
            metrics = parse_iperf(read_iperf_json(p))
        else:
            metrics = {"throughput_rx_Mbps": float("nan"), "jitter_ms": float("nan"), "loss_pct": float("nan")}
        r = {"class": klass}
        r.update(metrics)
        rows.append(r)
    return pd.DataFrame(rows).set_index("class")

def save_csv(df, out_csv):
    df.round(3).to_csv(out_csv)

def bar_plot(df, column, title, ylabel, out_png):
    plt.figure()
    ax = df[column].plot(kind="bar")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xlabel("Klasa")
    for p in ax.patches:
        h = p.get_height()
        if not (h != h):  # skip NaN (NaN != NaN)
            ax.annotate(f"{h:.2f}", (p.get_x() + p.get_width()/2., h),
                        ha="center", va="bottom", xytext=(0, 3), textcoords="offset points")
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()

def main():
    ap = argparse.ArgumentParser(description="Plot Scenario A (Baseline) EF/AF/BE stats (RX)")
    ap.add_argument("--run-dir", required=True, help="Katalog z wynikami scenariusza A")
    ap.add_argument("--out-prefix", default="/mnt/data/", help="Prefiks ścieżki wyjściowej (domyślnie /mnt/data)")
    args = ap.parse_args()

    df = load_metrics(args.run_dir)
    out_csv = os.path.join(args.out_prefix, "baseline_summary_rx.csv")
    save_csv(df, out_csv)

    bar_plot(df, "throughput_rx_Mbps", "Throughput (RX) — Baseline (Scenario A)", "Mb/s", os.path.join(args.out_prefix, "throughput_baseline_rx.png"))
    bar_plot(df, "loss_pct", "Packet loss — Baseline (Scenario A)", "%", os.path.join(args.out_prefix, "loss_baseline_rx.png"))
    bar_plot(df, "jitter_ms", "Jitter — Baseline (Scenario A)", "ms", os.path.join(args.out_prefix, "jitter_baseline_rx.png"))

    print("Zapisano:")
    print(out_csv)
    print(os.path.join(args.out_prefix, "throughput_baseline_rx.png"))
    print(os.path.join(args.out_prefix, "loss_baseline_rx.png"))
    print(os.path.join(args.out_prefix, "jitter_baseline_rx.png"))

if __name__ == "__main__":
    main()
