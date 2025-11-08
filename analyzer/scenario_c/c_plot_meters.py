
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json, argparse, re
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

def _bar_plot(labels, values, title, ylabel, out_png, ylim=None):
    fig = plt.figure()
    plt.bar(range(len(labels)), values, tick_label=labels)
    ax = plt.gca()
    _apply_axes_style(ax, title, ylabel, ylim=ylim)
    _annotate_bars(ax)
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close(fig)

def _read_json(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _parse_iperf(d):
    end = d.get("end", {})
    s = end.get("sum_received") or end.get("sum") or end.get("sum_sent") or {}
    bps = s.get("bits_per_second")
    tput = (bps / 1e6) if isinstance(bps, (int, float)) else float("nan")
    jitter = s.get("jitter_ms", float("nan"))
    lost = s.get("lost_packets", 0)
    sent = s.get("packets", 0)
    if "lost_percent" in s:
        loss = s["lost_percent"]
    else:
        loss = (100.0 * lost / sent) if sent else float("nan")
    return tput, jitter, loss

def _load_metrics_simple(run_dir):
    vals = {}
    for label, fn in [("EF","ef.json"), ("AF31","af31.json"), ("BE","be.json")]:
        p = os.path.join(run_dir, "clients", fn)
        t, j, l = _parse_iperf(_read_json(p))
        vals[label] = {"throughput": t, "jitter": j, "loss": l}
    # reindex to ORDER
    return {k: vals.get(k, {"throughput": float("nan"), "jitter": float("nan"), "loss": float("nan")}) for k in ORDER}

def _parse_meters_drops(run_dir):
    switch = os.path.join(run_dir, "switch")
    drops = {}
    if not os.path.isdir(switch):
        return drops
    for fname in os.listdir(switch):
        if not fname.endswith("_meters.txt"):
            continue
        try:
            txt = open(os.path.join(switch, fname), "r", encoding="utf-8", errors="ignore").read()
            import re as _re
            for block in _re.split(r"(?=meter\s*=\s*\d+)", txt, flags=_re.IGNORECASE):
                m_id = _re.search(r"meter\s*=\s*(\d+)", block, _re.IGNORECASE)
                if not m_id:
                    continue
                mid = int(m_id.group(1))
                m_pkt = _re.search(r"(?:pkt_count|packet_count)\s*[:=]\s*(\d+)", block, _re.IGNORECASE)
                d = int(m_pkt.group(1)) if m_pkt else 0
                drops[mid] = drops.get(mid, 0) + d
        except Exception:
            pass
    return drops

def main():
    ap = argparse.ArgumentParser(description="Plot Scenario C (Policing / meters) charts")
    ap.add_argument("--run-dir", required=True, help="Katalog z wynikami scenariusza C")
    ap.add_argument("--out-prefix", default="/mnt/data/", help="Prefiks ścieżki wyjściowej")
    # Jednolite skale
    ap.add_argument("--ylim-throughput", nargs=2, type=float, default=[0.0, 10.0], metavar=("YMIN","YMAX"))
    ap.add_argument("--ylim-loss",       nargs=2, type=float, default=[0.0, 100.0], metavar=("YMIN","YMAX"))
    ap.add_argument("--ylim-jitter",     nargs=2, type=float, default=[0.0, 50.0], metavar=("YMIN","YMAX"))
    args = ap.parse_args()

    vals = _load_metrics_simple(args.run_dir)
    labels = list(ORDER)

    _bar_plot(labels, [vals[k]["throughput"] for k in labels],
              "Throughput (RX) — Policing (Scenario C)", "Mb/s",
              os.path.join(args.out_prefix, "c_throughput_rx.png"),
              ylim=tuple(args.ylim_throughput))
    _bar_plot(labels, [vals[k]["loss"] for k in labels],
              "Packet loss — Policing (Scenario C)", "%",
              os.path.join(args.out_prefix, "c_loss_rx.png"),
              ylim=tuple(args.ylim_loss))
    _bar_plot(labels, [vals[k]["jitter"] for k in labels],
              "Jitter — Policing (Scenario C)", "ms",
              os.path.join(args.out_prefix, "c_jitter_rx.png"),
              ylim=tuple(args.ylim_jitter))

    md = _parse_meters_drops(args.run_dir)
    if md:
        mlab = [f"m{m}" for m in sorted(md.keys())]
        mval = [md[m] for m in sorted(md.keys())]
        _bar_plot(mlab, mval, "Meter drops per meter_id", "packets",
                  os.path.join(args.out_prefix, "c_meter_drops.png"))

    print("OK: zapisano C-wykresy do", args.out_prefix)

if __name__ == "__main__":
    main()
