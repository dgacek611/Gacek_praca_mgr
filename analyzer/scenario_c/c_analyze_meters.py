#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze Scenario C: Policing (OpenFlow meters) — cięcie nadmiaru.
- Zbiera statystyki iperf3 (EF/AF31/BE) oraz ping.
- Weryfikuje obecność meterów w flowach oraz BRAK OUTPUT w Table 0.
- Parsuje "dump-meters" i "meter-stats" z OVS (dla s1/s2/s3).
- Generuje raport Markdown + CSV zbiorczy (iperf + statystyki meterów).
Struktura katalogu wejściowego (jak generuje run_traffic.py):
run_dir/
  clients/
    ef.json, af31.json, be.json, ping.txt
  switch/
    s1_flows.txt, s2_flows.txt, s3_flows.txt
    s1_meters.txt, s2_meters.txt, s3_meters.txt
    <iface>_tc.txt (opcjonalnie – do porównania z B; nie wymagane)
"""
import os, re, csv, json, argparse
from typing import Dict, Any, List, Tuple
from datetime import datetime

# -------------------------- Iperf / Ping -------------------------------------

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
        "rtt_mdev_ms": float("nan"),
        "packet_loss_pct": float("nan"),
    }
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()

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

        if math.isnan(out["rtt_avg_ms"]) or math.isnan(out["packet_loss_pct"]):
            times = [float(x.replace(",", ".")) 
                     for x in re.findall(r"time=([\d.,]+)\s*ms", txt)]
            seqs  = [int(x) for x in re.findall(r"icmp_seq\s*=\s*(\d+)", txt, re.IGNORECASE)]
            if times:
                out["rtt_min_ms"] = min(times)
                out["rtt_avg_ms"] = sum(times)/len(times)
                out["rtt_max_ms"] = max(times)
                if len(times) > 1:
                    out["rtt_mdev_ms"] = stats.pstdev(times)
            if seqs:
                sent_est = max(seqs) - min(seqs) + 1
                rcvd = len(seqs)
                if sent_est > 0:
                    out["packet_loss_pct"] = max(0.0, 100.0 * (1.0 - rcvd / sent_est))
    except Exception:
        pass
    return out

# -------------------------- OVS flows (Table 0/1 sanity) ----------------------

def parse_flows_table0(path: str) -> Dict[str, Any]:
    """
    Sprawdza, czy w Table 0 nie ma OUTPUT; oczekujemy meter + goto:1, a OUTPUT dopiero w Table 1.
    Zwraca:
      { 'table0_rules': N, 'table0_with_output': M, 'table0_with_meter': K, 'table0_with_set_queue': Q }
    """
    out = {"table0_rules": 0, "table0_with_output": 0, "table0_with_meter": 0, "table0_with_set_queue": 0}
    try:
        txt = open(path, "r", encoding="utf-8", errors="ignore").read().lower()
    except Exception:
        return out
    for line in txt.splitlines():
        if "table=" not in line:
            continue
        m = re.search(r"table\s*=\s*(\d+)", line)
        if not m:
            continue
        t = int(m.group(1))
        if t != 0:
            continue
        out["table0_rules"] += 1
        if " actions=" in line:
            if re.search(r"\boutput\b", line):
                out["table0_with_output"] += 1
            if re.search(r"\bmeter\b", line):
                out["table0_with_meter"] += 1
            if re.search(r"set_queue\(|set_queue\b", line):
                out["table0_with_set_queue"] += 1
    return out

# -------------------------- OVS meters parser (POPRAWIONY) --------------------

def parse_meters_stats(path: str) -> Dict[str, Any]:
    """
    Parsuje łączony plik (dump-meters + meter-stats) i zwraca:
    { 'meters': { mid: {'rate_kbps', 'burst_kb', 'drops_pkts', 'drops_bytes'} } }
    Uwaga: 'drops_*' pochodzą WYŁĄCZNIE z band DROP (nie z packet_in_count).
    """
    out = {"meters": {}}
    try:
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        return out

    # 1) Rozbij na bloki po meter=<id> / meter:<id> / meter-id=<id>
    blocks = re.split(r"(?=meter(?:-id)?\s*[:=]\s*\d+)", txt, flags=re.IGNORECASE)

    for block in blocks:
        m_id = re.search(r"meter(?:-id)?\s*[:=]\s*(\d+)", block, re.IGNORECASE)
        if not m_id:
            continue
        mid = int(m_id.group(1))

        rec = out["meters"].setdefault(mid, {
            "rate_kbps": None,
            "burst_kb": None,
            "drops_pkts": None,
            "drops_bytes": None,
        })

        # 2) Konfiguracja (dump-meters)
        m_rate  = re.search(r"\brate\s*=\s*(\d+)\b", block)
        m_burst = re.search(r"\bburst[_\s]*size\s*=?\s*(\d+)\b", block, re.IGNORECASE)
        if m_rate:
            rec["rate_kbps"] = int(m_rate.group(1))
        if m_burst:
            rec["burst_kb"] = int(m_burst.group(1))  # w OF to kbit; nazwa kolumny zostaje 'kb'

        # 3) Statystyki bandu DROP
        # Najpierw spróbuj jedną parą (packet_count + byte_count) w tej samej linii po numerze bandu.
        m_pair = re.search(
            r"\bbands?\s*:\s*(?:\n\s*)?\d+\s*:\s*.*?\bpacket_count\s*[:=]\s*(\d+)\s+.*?\bbyte_count\s*[:=]\s*(\d+)",
            block, re.IGNORECASE | re.DOTALL
        )
        if m_pair:
            rec["drops_pkts"] = int(m_pair.group(1))
            rec["drops_bytes"] = int(m_pair.group(2))
        else:
            # Jeśli nie, spróbuj wyłuskać je osobno z sekcji 'bands:' ...
            m_band_pkt = re.search(
                r"\bbands?\s*:\s*(?:\n\s*)?\d+\s*:\s*.*?\bpacket_count\s*[:=]\s*(\d+)",
                block, re.IGNORECASE | re.DOTALL
            )
            m_band_byt = re.search(
                r"\bbands?\s*:\s*(?:\n\s*)?\d+\s*:\s*.*?\bbyte_count\s*[:=]\s*(\d+)",
                block, re.IGNORECASE | re.DOTALL
            )
            # ... albo z wariantu 'band-stats { ... }'
            if not m_band_pkt:
                m_band_pkt = re.search(
                    r"\bband[-\s]*stats\b.*?\bpacket_count\s*[:=]\s*(\d+)",
                    block, re.IGNORECASE | re.DOTALL
                )
            if not m_band_byt:
                m_band_byt = re.search(
                    r"\bband[-\s]*stats\b.*?\bbyte_count\s*[:=]\s*(\d+)",
                    block, re.IGNORECASE | re.DOTALL
                )

            if m_band_pkt:
                rec["drops_pkts"] = int(m_band_pkt.group(1))
            if m_band_byt:
                rec["drops_bytes"] = int(m_band_byt.group(1))

    return out

# -------------------------- Analiza całego runu --------------------------------

def analyze_run(run_dir: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    clients = os.path.join(run_dir, "clients")
    switch = os.path.join(run_dir, "switch")

    # iperf per klasa
    iperf_files = {
        "EF": os.path.join(clients, "ef.json"),
        "AF31": os.path.join(clients, "af31.json"),
        "BE": os.path.join(clients, "be.json"),
    }
    iperf_stats = {}
    for cls, path in iperf_files.items():
        if os.path.exists(path):
            tput, jitter, loss = parse_iperf(read_iperf_json(path))
        else:
            tput = jitter = loss = float("nan")
        iperf_stats[cls] = {
            "throughput_rx_Mbps": tput,
            "jitter_ms": jitter,
            "loss_pct": loss,
        }
    out["iperf"] = iperf_stats

    # ping
    ping_path = os.path.join(clients, "ping.txt")
    out["ping"] = parse_ping_txt(ping_path) if os.path.exists(ping_path) else {}

    # flows (kontrola table 0)
    flows_summary = {}
    flow_files = [os.path.join(switch, f) for f in os.listdir(switch) if f.endswith("_flows.txt")] if os.path.isdir(switch) else []
    for f in flow_files:
        flows_summary[os.path.basename(f)] = parse_flows_table0(f)
    out["flows_table0"] = flows_summary

    # meters (s1/s2/s3)
    meters_summary = {}
    meter_files = [os.path.join(switch, f) for f in os.listdir(switch) if f.endswith("_meters.txt")] if os.path.isdir(switch) else []
    for f in meter_files:
        meters_summary[os.path.basename(f)] = parse_meters_stats(f)
    out["meters"] = meters_summary

    # prosta walidacja scenariusza C
    any_table0 = any(v.get("table0_rules", 0) > 0 for v in flows_summary.values()) if flows_summary else False
    any_table0_output = any(v.get("table0_with_output", 0) > 0 for v in flows_summary.values()) if flows_summary else False
    any_table0_meter  = any(v.get("table0_with_meter", 0)  > 0 for v in flows_summary.values()) if flows_summary else False
    any_meter_files   = bool(meters_summary)

    has_set_queue = any(v.get("table0_with_set_queue", 0)  > 0 for v in flows_summary.values()) if flows_summary else False

    out["scenarioC_checks"] = {
        "table0_present": any_table0,
        "table0_has_meter": any_table0_meter,
        "table0_has_output": any_table0_output,   # powinno być False,
        "table0_has_set_queue": has_set_queue,
        "has_meter_dumps": any_meter_files,
        "note": "Scenariusz C: oczekujemy InstructionMeter w Table 0 i OUTPUT dopiero w Table 1; metery powinny raportować dropy przy przekroczeniu rate."
    }
    return out

# -------------------------- Raporty -------------------------------------------

def write_report(analysis: Dict[str, Any], out_md: str, out_csv_ip: str, out_csv_m: str) -> None:
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(f"# Scenario C — Policing (OpenFlow meters) report ({now})")
    lines.append("")
    # Iperf
    iperf = analysis.get("iperf", {})
    lines.append("## Iperf3 per klasa (RX)")
    lines.append("Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]")
    lines.append("---|---:|---:|---:")
    for cls in ("EF", "AF31", "BE"):
        s = iperf.get(cls, {})
        lines.append(f"{cls} | {s.get('throughput_rx_Mbps', float('nan')):.3f} | {s.get('jitter_ms', float('nan')):.3f} | {s.get('loss_pct', float('nan')):.3f}")
    lines.append("")
    # Ping
    ping = analysis.get("ping", {})
    lines.append("## Ping (h1→h2)")
    if ping:
        lines.append(f"- Packet loss: {ping.get('packet_loss_pct', float('nan')):.2f}%")
        lines.append(f"- RTT min/avg/max/mdev: {ping.get('rtt_min_ms', float('nan')):.3f} / {ping.get('rtt_avg_ms', float('nan')):.3f} / {ping.get('rtt_max_ms', float('nan')):.3f} / {ping.get('rtt_mdev_ms', float('nan')):.3f} ms")
    else:
        lines.append("- brak danych ping.txt")
    lines.append("")

    # Flows sanity
    lines.append("## Kontrole w Table 0 (OVS flows)")
    checks = analysis.get("scenarioC_checks", {})
    lines.append(f"- Reguły w Table 0 obecne: *{checks.get('table0_present', False)}*")
    lines.append(f"- InstructionMeter w Table 0: *{checks.get('table0_has_meter', False)}*")
    lines.append(f"- SetQueue w Table 0 (oznaka trybu kolejkowania, NIE policing): *{checks.get('table0_has_set_queue', False)}*")
    lines.append(f"- OUTPUT w Table 0 (niepożądane): *{checks.get('table0_has_output', False)}*")
    lines.append("Plik | table0_rules | table0_with_meter | table0_with_set_queue | table0_with_output")
    lines.append("---|---:|---:|---:")
    for fname, v in (analysis.get("flows_table0") or {}).items():
        lines.append(f"{fname} | {v.get('table0_rules',0)} | {v.get('table0_with_meter',0)} | {v.get('table0_with_set_queue',0)} | {v.get('table0_with_output',0)}")
    lines.append("")

    # Meters
    lines.append("## Statystyki meterów (dump-meters + dump-meter-stats)")
    lines.append(f"- Zrzuty metery obecne: *{checks.get('has_meter_dumps', False)}*")
    lines.append("Plik | meter_id | rate_kbps | burst_kb | drops_pkts | drops_bytes")
    lines.append("---|---:|---:|---:|---:|---:")
    meters = analysis.get("meters", {})
    for fname, data in meters.items():
        ms = data.get("meters", {})
        if not ms:
            lines.append(f"{fname} |  |  |  |  | ")
        for mid, s in sorted(ms.items()):
            lines.append(f"{fname} | {mid} | {s.get('rate_kbps','')} | {s.get('burst_kb','')} | {s.get('drops_pkts','')} | {s.get('drops_bytes','')}")

    lines.append("")
    lines.append(f"*Uwaga*: {checks.get('note','')}")
    lines.append("")

    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # CSV 1: iperf summary
    with open(out_csv_ip, "w", newline="", encoding="utf-8") as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["class","throughput_rx_Mbps","jitter_ms","loss_pct"])
        for cls in ("EF", "AF31", "BE"):
            s = iperf.get(cls, {})
            w.writerow([cls, s.get("throughput_rx_Mbps",""), s.get("jitter_ms",""), s.get("loss_pct","")])

    # CSV 2: meters summary (flattened)
    with open(out_csv_m, "w", newline="", encoding="utf-8") as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["source_file","meter_id","rate_kbps","burst_kb","drops_pkts","drops_bytes"])
        for fname, data in (analysis.get("meters") or {}).items():
            for mid, s in sorted((data.get("meters") or {}).items()):
                w.writerow([fname, mid, s.get("rate_kbps",""), s.get("burst_kb",""), s.get("drops_pkts",""), s.get("drops_bytes","")])

def main():
    ap = argparse.ArgumentParser(description="Analyze Scenario C: Policing (OpenFlow meters) run directory.")
    ap.add_argument("--run-dir", required=True, help="Directory created by run_traffic.py (scenario C)")
    ap.add_argument("--out-dir", default=None, help="Gdzie zapisać raporty; domyślnie do --run-dir")
    args = ap.parse_args()

    analysis = analyze_run(args.run_dir)

    out_dir = args.out_dir or args.run_dir
    os.makedirs(out_dir, exist_ok=True)
    out_md  = os.path.join(out_dir, "policing_meters_report.md")
    out_csv_ip = os.path.join(out_dir, "policing_summary_rx.csv")
    out_csv_m  = os.path.join(out_dir, "policing_meters_stats.csv")
    write_report(analysis, out_md, out_csv_ip, out_csv_m)

    print("OK. Wygenerowano:")
    print(" -", out_md)
    print(" -", out_csv_ip)
    print(" -", out_csv_m)

if __name__ == "__main__":
    main()
