#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, re, argparse, csv
from typing import Dict, Any, List, Tuple
from datetime import datetime

def read_iperf_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_iperf(stream: Dict[str, Any]) -> Tuple[float, float, float]:
    """
    Zwraca (throughput_rx_Mbps, jitter_ms, loss_pct).
    Preferuje statystyki po stronie odbiorcy (sum_received),
    z fallbackiem do sum / sum_sent.
    """
    try:
        end = stream.get("end", {})
        summary = end.get("sum_received") or end.get("sum") or end.get("sum_sent")
        if not summary:
            return (float("nan"), float("nan"), float("nan"))
        tput_mbps = summary.get("bits_per_second", float("nan")) / 1e6
        # jitter w UDP iperf3 bywa tylko w 'sum'; jeśli brak, spróbuj stamtąd
        jitter_ms = summary.get("jitter_ms", end.get("sum", {}).get("jitter_ms", float("nan")))
        lost = summary.get("lost_packets", end.get("sum", {}).get("lost_packets", 0))
        sent = summary.get("packets", end.get("sum", {}).get("packets", 0))
        loss_pct = summary.get("lost_percent") if "lost_percent" in summary else ((100.0 * lost / sent) if sent else float("nan"))
        return (tput_mbps, jitter_ms, loss_pct)
    except Exception:
        return (float("nan"), float("nan"), float("nan"))

def parse_ping_txt(path: str) -> Dict[str, float]:
    import math, statistics as stats
    out = {
        "rtt_min_ms": float("nan"),
        "rtt_avg_ms": float("nan"),
        "rtt_max_ms": float("nan"),
        # iputils podaje mdev (mean deviation), my damy przybliżenie: stdev
        "rtt_mdev_ms": float("nan"),
        "packet_loss_pct": float("nan"),
    }
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()

        # 1) jeśli są klasyczne statystyki — użyj ich
        m_stats = re.search(
            r"=\s*([\d.,]+)\s*/\s*([\d.,]+)\s*/\s*([\d.,]+)(?:\s*/\s*([\d.,]+))?\s*ms",
            txt, re.IGNORECASE)
        m_loss  = re.search(r"(\d+(?:[.,]\d+)?)\s*%\s*(?:packet\s*loss|strat|perte|perdidos)", 
                            txt, re.IGNORECASE)
        if m_stats:
            out["rtt_min_ms"] = float(m_stats.group(1).replace(",", "."))
            out["rtt_avg_ms"] = float(m_stats.group(2).replace(",", "."))
            out["rtt_max_ms"] = float(m_stats.group(3).replace(",", "."))
            if m_stats.group(4):
                out["rtt_mdev_ms"] = float(m_stats.group(4).replace(",", "."))
        if m_loss:
            out["packet_loss_pct"] = float(m_loss.group(1).replace(",", "."))

        # 2) Fallback: policz z pojedynczych odpowiedzi
        if math.isnan(out["rtt_avg_ms"]) or math.isnan(out["packet_loss_pct"]):
            times = [float(x.replace(",", ".")) 
                     for x in re.findall(r"time=([\d.,]+)\s*ms", txt)]
            seqs  = [int(x) for x in re.findall(r"icmp_seq\s*=\s*(\d+)", txt, re.IGNORECASE)]
            if times:
                out["rtt_min_ms"] = min(times)
                out["rtt_avg_ms"] = sum(times)/len(times)
                out["rtt_max_ms"] = max(times)
                if len(times) > 1:
                    out["rtt_mdev_ms"] = stats.pstdev(times)  # dobre przybliżenie
            if seqs:
                sent_est = max(seqs) - min(seqs) + 1  # zakładamy ciągłą numerację
                rcvd = len(seqs)
                if sent_est > 0:
                    out["packet_loss_pct"] = max(0.0, 100.0 * (1.0 - rcvd / sent_est))
    except Exception:
        pass
    return out

def detect_tbf_ifaces(switch_dir: str) -> List[str]:
    if not os.path.isdir(switch_dir):
        return []
    ifaces = []
    for fname in os.listdir(switch_dir):
        if fname.endswith("_tc.txt"):
            try:
                txt = open(os.path.join(switch_dir, fname), "r", encoding="utf-8", errors="ignore").read().lower()
                if "qdisc tbf" in txt:
                    ifaces.append(fname.replace("_tc.txt",""))
            except Exception:
                pass
    return sorted(ifaces)

def check_no_qos_flows(flows_paths: List[str]) -> bool:
    patt = re.compile(r"(ip_dscp|set_queue|meter)", re.IGNORECASE)
    for p in flows_paths:
        try:
            if patt.search(open(p, "r", encoding="utf-8", errors="ignore").read()):
                return False
        except Exception:
            pass
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
        lines.append(
            f"{cls} | "
            f"{s.get('throughput_rx_Mbps', float('nan')):.3f} | "
            f"{s.get('jitter_ms', float('nan')):.3f} | "
            f"{s.get('loss_pct', float('nan')):.3f}"
        )
    lines.append("")
    ping = analysis.get("ping", {})
    lines.append("## Ping (h1→h2)")
    if ping:
        lines.append(f"- Packet loss: {ping.get('packet_loss_pct', float('nan')):.2f}%")
        lines.append(
            "- RTT min/avg/max/mdev: "
            f"{ping.get('rtt_min_ms', float('nan')):.3f} / "
            f"{ping.get('rtt_avg_ms', float('nan')):.3f} / "
            f"{ping.get('rtt_max_ms', float('nan')):.3f} / "
            f"{ping.get('rtt_mdev_ms', float('nan')):.3f} ms"
        )
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

    # CSV (RX, per run)
    with open(out_csv, "w", newline="", encoding="utf-8") as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["class","throughput_rx_Mbps","jitter_ms","loss_pct"])
        for cls in ("EF", "AF31", "BE"):
            s = iperf.get(cls, {})
            w.writerow([
                cls,
                s.get("throughput_rx_Mbps",""),
                s.get("jitter_ms",""),
                s.get("loss_pct","")
            ])

def main():
    ap = argparse.ArgumentParser(description="Analyze Scenario A baseline results.")
    ap.add_argument("--run-dir", help="Pojedynczy katalog run (jak z run_traffic.py)")
    ap.add_argument("--runs-root", help="Katalog zawierający wiele katalogów run (każdy osobno analizowany)")
    ap.add_argument("--out-dir", default=None, help="Gdzie zapisać raporty; domyślnie: do danego katalogu run / runs-root")
    args = ap.parse_args()

    if not args.run_dir and not args.runs_root:
        ap.error("Podaj albo --run-dir (pojedynczy run), albo --runs-root (wiele runów).")

    # Tryb: wiele runów w jednym katalogu
    if args.runs_root:
        root = args.runs_root
        if not os.path.isdir(root):
            raise SystemExit(f"--runs-root '{root}' nie jest katalogiem")

        all_rows = []
        # każdy podkatalog traktujemy jako osobny run
        for name in sorted(os.listdir(root)):
            run_path = os.path.join(root, name)
            if not os.path.isdir(run_path):
                continue

            print(f"[i] Analiza runu: {run_path}")
            analysis = analyze_run(run_path)

            # raporty per-run – domyślnie do samego runu
            out_dir_run = args.out_dir or run_path
            os.makedirs(out_dir_run, exist_ok=True)
            out_md = os.path.join(out_dir_run, "baseline_report.md")
            out_csv = os.path.join(out_dir_run, "baseline_summary_rx.csv")
            write_report(analysis, out_md, out_csv)

            # zbiorczy wiersz do all_runs_summary_rx.csv
            iperf = analysis.get("iperf", {})
            for cls in ("EF", "AF31", "BE"):
                s = iperf.get(cls, {})
                all_rows.append({
                    "run": name,
                    "class": cls,
                    "throughput_rx_Mbps": s.get("throughput_rx_Mbps", ""),
                    "jitter_ms": s.get("jitter_ms", ""),
                    "loss_pct": s.get("loss_pct", ""),
                })

        # zapis zbiorczego CSV
        combo_out_dir = args.out_dir or args.runs_root
        os.makedirs(combo_out_dir, exist_ok=True)
        combo_csv = os.path.join(combo_out_dir, "all_runs_summary_rx.csv")
        with open(combo_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["run","class","throughput_rx_Mbps","jitter_ms","loss_pct"])
            w.writeheader()
            for row in all_rows:
                w.writerow(row)

        print(f"\nOK. Wygenerowano zbiorczy plik: {combo_csv}")

    # Tryb: pojedynczy run (tak jak wcześniej)
    if args.run_dir and not args.runs_root:
        run_dir = args.run_dir
        analysis = analyze_run(run_dir)

        out_dir = args.out_dir or run_dir
        os.makedirs(out_dir, exist_ok=True)
        out_md = os.path.join(out_dir, "baseline_report.md")
        out_csv = os.path.join(out_dir, "baseline_summary_rx.csv")
        write_report(analysis, out_md, out_csv)

        print(f"OK. Wygenerowano:\n - {out_md}\n - {out_csv}")

if __name__ == "__main__":
    main()
