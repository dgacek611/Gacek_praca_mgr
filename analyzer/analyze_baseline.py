#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, re, argparse, statistics
from typing import Dict, Any, List, Tuple
from datetime import datetime

def read_iperf_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_iperf(stream: Dict[str, Any]) -> Tuple[float, float, float]:
    """
    Returns (throughput_rx_Mbps, jitter_ms_avg, loss_percent)
    for UDP iperf3 JSON. Prefer receiver stats (sum_received).
    """
    try:
        summary = stream["end"].get("sum_received", stream["end"].get("sum", {}))
        tput_mbps = summary.get("bits_per_second", 0.0) / 1e6
        jitter_ms = summary.get("jitter_ms", 0.0)
        lost = summary.get("lost_packets", 0)
        sent = summary.get("packets", 0)
        loss_pct = (100.0 * lost / sent) if sent else 0.0
        return (tput_mbps, jitter_ms, loss_pct)
    except Exception:
        return (float("nan"), float("nan"), float("nan"))

def parse_ping_txt(path: str) -> Dict[str, float]:
    stats = {"rtt_min_ms": float("nan"), "rtt_avg_ms": float("nan"),
             "rtt_max_ms": float("nan"), "rtt_mdev_ms": float("nan"),
             "packet_loss_pct": float("nan")}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
        m_loss = re.search(r"(\\d+(?:\\.\\d+)?)% packet loss", txt)
        if m_loss:
            stats["packet_loss_pct"] = float(m_loss.group(1))
        m = re.search(r"rtt [a-z/]+= ([\\d\\.]+)/([\\d\\.]+)/([\\d\\.]+)/([\\d\\.]+) ms", txt)
        if m:
            stats["rtt_min_ms"] = float(m.group(1))
            stats["rtt_avg_ms"] = float(m.group(2))
            stats["rtt_max_ms"] = float(m.group(3))
            stats["rtt_mdev_ms"] = float(m.group(4))
    except Exception:
        pass
    return stats

def detect_tbf_ifaces(switch_dir: str) -> List[str]:
    if not os.path.isdir(switch_dir):
        return []
    ifaces = []
    for fname in os.listdir(switch_dir):
        if not fname.endswith("_tc.txt"):
            continue
        try:
            with open(os.path.join(switch_dir, fname), "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read().lower()
            if "qdisc tbf" in txt:
                ifaces.append(fname.replace("_tc.txt",""))
        except Exception:
            continue
    return sorted(ifaces)

def check_no_qos_flows(flows_paths: List[str]) -> bool:
    patt = re.compile(r"(ip_dscp|set_queue|meter)", re.IGNORECASE)
    for p in flows_paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
            if patt.search(txt):
                return False
        except Exception:
            continue
    return True

def analyze_run(run_dir: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    clients = os.path.join(run_dir, "clients")
    switch = os.path.join(run_dir, "switch")

    iperf_files = {
        "EF": os.path.join(clients, "ef.json"),
        "AF31": os.path.join(clients, "af31.json"),
        "BE": os.path.join(clients, "be.json"),
    }
    iperf_stats = {}
    for cls, path in iperf_files.items():
        if os.path.exists(path):
            stats = parse_iperf(read_iperf_json(path))
        else:
            stats = (float("nan"), float("nan"), float("nan"))
        iperf_stats[cls] = {
            "throughput_rx_Mbps": stats[0],
            "jitter_ms": stats[1],
            "loss_pct": stats[2],
        }
    out["iperf"] = iperf_stats

    ping_path = os.path.join(clients, "ping.txt")
    out["ping"] = parse_ping_txt(ping_path) if os.path.exists(ping_path) else {}

    tbf_ifaces = detect_tbf_ifaces(switch)
    flow_files = [os.path.join(switch, f) for f in os.listdir(switch) if f.endswith("_flows.txt")] if os.path.isdir(switch) else []
    out["no_qos_flows_in_table0"] = check_no_qos_flows(flow_files)

    out["scenarioA_checks"] = {
        "tbf_present": bool(tbf_ifaces),
        "tbf_ifaces": tbf_ifaces,
        "no_qos_flows": out["no_qos_flows_in_table0"],
        "note": "W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort."
    }
    return out

def write_report(analysis: Dict[str, Any], out_md: str, out_csv: str) -> None:
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(f"# Scenario A — Baseline report ({now})")
    lines.append("")
    iperf = analysis.get("iperf", {})
    lines.append("## Iperf3 per klasa (RX)")
    lines.append("Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]")
    lines.append("---|---:|---:|---:")
    for cls in ("EF", "AF31", "BE"):
        s = iperf.get(cls, {})
        lines.append(f"{cls} | {s.get('throughput_rx_Mbps', float('nan')):.3f} | {s.get('jitter_ms', float('nan')):.3f} | {s.get('loss_pct', float('nan')):.3f}")
    lines.append("")
    ping = analysis.get("ping", {})
    lines.append("## Ping (h1→h2)")
    if ping:
        lines.append(f"- Packet loss: {ping.get('packet_loss_pct', float('nan')):.2f}%")
        lines.append(f"- RTT min/avg/max/mdev: {ping.get('rtt_min_ms', float('nan')):.3f} / {ping.get('rtt_avg_ms', float('nan')):.3f} / {ping.get('rtt_max_ms', float('nan')):.3f} / {ping.get('rtt_mdev_ms', float('nan')):.3f} ms")
    else:
        lines.append("- brak danych ping.txt")
    lines.append("")
    checks = analysis.get("scenarioA_checks", {})
    tbf_ifaces = checks.get("tbf_ifaces", [])
    lines.append("## Kontrole poprawności")
    lines.append(f"- TBF obecny: **{checks.get('tbf_present', False)}**{(' (' + ', '.join(tbf_ifaces) + ')') if tbf_ifaces else ''}")
    lines.append(f"- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **{checks.get('no_qos_flows', False)}**")
    lines.append(f"- Uwaga: {checks.get('note','')}")
    lines.append("")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # CSV (RX)
    import csv
    with open(out_csv, "w", newline="", encoding="utf-8") as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["class","throughput_rx_Mbps","jitter_ms","loss_pct"])
        for cls in ("EF", "AF31", "BE"):
            s = iperf.get(cls, {})
            w.writerow([cls, s.get("throughput_rx_Mbps",""), s.get("jitter_ms",""), s.get("loss_pct","")])

def main():
    ap = argparse.ArgumentParser(description="Analyze Scenario A baseline run directory.")
    ap.add_argument("--run-dir", required=True, help="Directory created by run_traffic.py (scenario A)")
    ap.add_argument("--out-dir", default=None, help="Gdzie zapisać raporty; domyślnie do --run-dir")
    args = ap.parse_args()

    analysis = analyze_run(args.run_dir)

    out_dir = args.out_dir or args.run_dir
    os.makedirs(out_dir, exist_ok=True)
    out_md = os.path.join(out_dir, "baseline_report.md")
    out_csv = os.path.join(out_dir, "baseline_summary_rx.csv")
    write_report(analysis, out_md, out_csv)

    print(f"OK. Wygenerowano:\\n - {out_md}\\n - {out_csv}")

if __name__ == "__main__":
    main()
