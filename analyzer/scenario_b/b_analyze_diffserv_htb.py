
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze Scenario B: DiffServ + HTB (shaping/priorities on bottleneck).
- Zbiera statystyki iperf3 (EF/AF31/BE) oraz ping.
- Weryfikuje klasyfikację na poziomie OVS (ip_dscp / set_queue).
- Parsuje statystyki kolejek HTB z dumpu `tc -s qdisc/class show dev IFACE`.
- Opcjonalnie parsuje statystyki OVS QoS/queue z `ovs-appctl qos/show IFACE`.
- Generuje raport Markdown oraz CSV-y pomocnicze.
Struktura katalogu wejściowego zakładana jest podobna jak w scenariuszu A:
run_dir/
  clients/
    ef.json, af31.json, be.json, ping.txt
  switch/
    <iface>_flows.txt             # "ovs-ofctl dump-flows" lub "ovs-appctl ofproto/trace/show"
    <iface>_tc.txt                # "tc -s qdisc show dev IFACE" + "tc -s class show dev IFACE" (może być w jednym pliku)
    <iface>_qos.txt               # "ovs-appctl qos/show IFACE" (opcjonalne)
Jeżeli nazwy/formaty różnią się – skrypt spróbuje zachować się możliwie odpornie.
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

# -------------------------- OVS flows (klasyfikacja) --------------------------

def parse_flows_for_qos(path: str) -> Dict[str, Any]:
    """
    Liczy obecność wzorców klasyfikacji: ip_dscp=46 (EF), ip_dscp=26/AF31, brak DSCP (BE),
    oraz akcje set_queue:N i set_field:XX->ip_dscp.
    Zwraca licznik wystąpień, aby potwierdzić klasyfikację.
    """
    counters = {
        "ip_dscp_ef": 0,     # 46
        "ip_dscp_af31": 0,   # 26 lub 0x1a
        "ip_dscp_any": 0,
        "set_queue_ef": 0,   # queue 1 (przykładowo)
        "set_queue_af": 0,   # queue 2
        "set_queue_be": 0,   # queue 0
        "set_field_to_dscp": 0,
        "has_meter": 0,
    }
    try:
        txt = open(path, "r", encoding="utf-8", errors="ignore").read().lower()
    except Exception:
        return counters

    # ip_dscp may appear as decimal or hex (e.g., 46 or 0x2e)
    counters["ip_dscp_ef"]   = len(re.findall(r"ip_dscp\s*=\s*(46|0x2e)", txt))
    counters["ip_dscp_af31"] = len(re.findall(r"ip_dscp\s*=\s*(26|0x1a)", txt))
    counters["ip_dscp_any"]  = len(re.findall(r"ip_dscp\s*=", txt))

    # set_queue
    counters["set_queue_ef"] = len(re.findall(r"set_queue\s*:\s*1", txt))
    counters["set_queue_af"] = len(re.findall(r"set_queue\s*:\s*2", txt))
    counters["set_queue_be"] = len(re.findall(r"set_queue\s*:\s*0", txt))

    # set_field to DSCP (some setups rewrite DSCP)
    counters["set_field_to_dscp"] = len(re.findall(r"set_field\s*:\s*(?:46|0x2e|26|0x1a)->ip_dscp", txt))

    # meters
    counters["has_meter"] = len(re.findall(r"\bmeter\b", txt))

    # Alternate match used by some OVS versions: "nw_tos" encodes DSCP<<2
    # EF(46)->0xb8(184), AF31(26)->0x68(104)
    ef_tos = len(re.findall(r"nw_tos\s*=\s*(184|0xb8)", txt))
    af_tos = len(re.findall(r"nw_tos\s*=\s*(104|0x68)", txt))
    any_tos = len(re.findall(r"nw_tos\s*=\s*\S+", txt))
    counters["ip_dscp_ef"] += ef_tos
    counters["ip_dscp_af31"] += af_tos
    counters["ip_dscp_any"] += any_tos


    return counters

# -------------------------- TC (HTB) parser ----------------------------------

_QDISC_RE = re.compile(r"qdisc\s+(\w+)\s+\S+\s+dev\s+(\S+)", re.IGNORECASE)
_CLASS_RE = re.compile(r"class\s+htb\s+(\S+)\s+parent\s+(\S+)\s+prio\s*(\d+)?", re.IGNORECASE)

def parse_tc_stats(path: str) -> Dict[str, Any]:
    """
    Parsuje zrzut "tc -s qdisc show dev IFACE" oraz/lub "tc -s class show dev IFACE" 
    (może być w jednym pliku) i stara się wyciągnąć:
    - obecność HTB,
    - statystyki klas HTB: classid, parent, prio, rate/ceil (jeśli są), packets/bytes/drops/overlimits/backlog.
    Zwraca: {
      'iface': 'ethX',
      'has_htb': True/False,
      'qdisc': [{'type':'htb','raw':line}, ...],
      'classes': { '1:10': {...}, '1:20': {...} }
    }
    """
    out = {
        "iface": None,
        "has_htb": False,
        "qdisc": [],
        "classes": {}
    }
    try:
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        return out

    # detect iface and qdiscs
    for m in _QDISC_RE.finditer(txt):
        qtype, dev = m.group(1).lower(), m.group(2)
        out["iface"] = out["iface"] or dev
        out["qdisc"].append({"type": qtype, "dev": dev})
        if qtype == "htb":
            out["has_htb"] = True

    # classes (robust extraction)
    for block in re.split(r"\n\s*\n", txt):
        if "class htb" not in block.lower():
            continue
        m = re.search(r"class\s+htb\s+(\S+)\s+parent\s+(\S+)(?:\s+prio\s*(\d+))?", block, re.IGNORECASE)
        if not m:
            continue
        classid, parent, prio = m.group(1), m.group(2), (m.group(3) or "")
        stats = {
            "parent": parent, "prio": prio,
            "rate": None, "ceil": None,
            "packets": None, "bytes": None, "drops": None, "overlimits": None,
            "backlog_bytes": None, "backlog_pkts": None
        }
        # rate/ceil
        r_rate = re.search(r"rate\s+([\d\.]+\w+)", block, re.IGNORECASE)
        r_ceil = re.search(r"ceil\s+([\d\.]+\w+)", block, re.IGNORECASE)
        if r_rate: stats["rate"] = r_rate.group(1)
        if r_ceil: stats["ceil"] = r_ceil.group(1)
        # packets/bytes drops/overlimits e.g., "Sent 12345 bytes 67 pkt (dropped 1, overlimits 2)"
        m_sent = re.search(r"sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt", block, re.IGNORECASE)
        if m_sent:
            stats["bytes"] = int(m_sent.group(1))
            stats["packets"] = int(m_sent.group(2))
        m_drop = re.search(r"dropped\s+(\d+)", block, re.IGNORECASE)
        if m_drop:
            stats["drops"] = int(m_drop.group(1))
        m_ovl = re.search(r"overlimits\s+(\d+)", block, re.IGNORECASE)
        if m_ovl:
            stats["overlimits"] = int(m_ovl.group(1))
        # backlog form like "backlog 0b 0p"
        m_b = re.search(r"backlog\s+(\d+)(?:b|bytes)\s+(\d+)(?:p|pkts?)", block, re.IGNORECASE)
        if m_b:
            stats["backlog_bytes"] = int(m_b.group(1))
            stats["backlog_pkts"] = int(m_b.group(2))

        out["classes"][classid] = stats

    return out

# -------------------------- OVS QoS (kolejki 0/1/2) --------------------------

def parse_ovs_qos(path: str) -> Dict[str, Any]:
    """
    Parsuje 'ovs-appctl qos/show IFACE'.
    Szuka queue 0/1/2 i ich counters: packets/bytes/dropped/errors.
    """
    out = {"iface": None, "queues": {}}
    try:
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        return out
    m_dev = re.search(r"port\s+(\S+)", txt, re.IGNORECASE)
    if m_dev:
        out["iface"] = m_dev.group(1)
    for qid in ("0", "1", "2", "3"):
        block = re.search(rf"queue\s+{qid}\s*:(.*?)(?:\n\s*\n|\Z)", txt, re.IGNORECASE | re.DOTALL)
        if not block:
            continue
        b = block.group(1)
        q = {
            "packets": _int_or_none(re.search(r"packets\s*:\s*(\d+)", b)),
            "bytes":   _int_or_none(re.search(r"bytes\s*:\s*(\d+)", b)),
            "dropped": _int_or_none(re.search(r"dropped\s*:\s*(\d+)", b)),
            "errors":  _int_or_none(re.search(r"errors\s*:\s*(\d+)", b)),
        }
        out["queues"][qid] = q
    return out

def _int_or_none(m):
    return int(m.group(1)) if m else None

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

    # flows (klasyfikacja)
    flow_files = [os.path.join(switch, f) for f in os.listdir(switch) if f.endswith("_flows.txt")] if os.path.isdir(switch) else []
    flows_summary = {}
    for f in flow_files:
        flows_summary[os.path.basename(f)] = parse_flows_for_qos(f)
    out["flows"] = flows_summary

    # tc / htb
    tc_files = [os.path.join(switch, f) for f in os.listdir(switch) if f.endswith("_tc.txt")] if os.path.isdir(switch) else []
    htb_summary = {}
    for f in tc_files:
        htb_summary[os.path.basename(f)] = parse_tc_stats(f)
    out["htb"] = htb_summary

    # ovs qos (opcjonalne)
    qos_files = [os.path.join(switch, f) for f in os.listdir(switch) if f.endswith("_qos.txt")] if os.path.isdir(switch) else []
    qos_summary = {}
    for f in qos_files:
        qos_summary[os.path.basename(f)] = parse_ovs_qos(f)
    out["qos"] = qos_summary

    # szybkie flagi na potrzeby walidacji
    out["scenarioB_checks"] = {
        "has_htb": any(v.get("has_htb") for v in htb_summary.values()),
        "has_set_queue": any((vs.get("set_queue_ef",0)+vs.get("set_queue_af",0)+vs.get("set_queue_be",0))>0 for vs in flows_summary.values()),
        "has_dscp_match": any(vs.get("ip_dscp_any",0)>0 for vs in flows_summary.values()),
        "note": "Scenariusz B: oczekujemy priorytetów i kształtowania (HTB) + prawidłowej klasyfikacji DSCP→kolejki."
    }
    return out

# -------------------------- Raporty -------------------------------------------

def write_report(analysis: Dict[str, Any], out_md: str, out_csv_ip: str, out_csv_q: str) -> None:
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(f"# Scenario B — DiffServ + HTB report ({now})")
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
    # Flows
    lines.append("## Kontrole klasyfikacji (OVS flows)")
    checks = analysis.get("scenarioB_checks", {})
    lines.append(f"- HTB obecny: **{checks.get('has_htb', False)}**")
    lines.append(f"- set_queue w flowach: **{checks.get('has_set_queue', False)}**")
    lines.append(f"- Dopasowania DSCP w flowach: **{checks.get('has_dscp_match', False)}**")
    lines.append("")
    lines.append("Plik | ip_dscp(any) | EF(dscp=46) | AF31(dscp=26) | set_queue:0 | :1 | :2 | set_field->ip_dscp | meter")
    lines.append("---|---:|---:|---:|---:|---:|---:|---:|---:")
    for fname, v in (analysis.get("flows") or {}).items():
        lines.append(f"{fname} | {v.get('ip_dscp_any',0)} | {v.get('ip_dscp_ef',0)} | {v.get('ip_dscp_af31',0)} | {v.get('set_queue_be',0)} | {v.get('set_queue_ef',0)} | {v.get('set_queue_af',0)} | {v.get('set_field_to_dscp',0)} | {v.get('has_meter',0)}")
    lines.append("")

    # HTB (tc)
    lines.append("## Statystyki HTB (tc -s) na interfejsach „wąskiego gardła”")
    if not analysis.get("htb"):
        lines.append("- brak plików *_tc.txt")
    else:
        lines.append("Plik/klasa | parent | prio | rate | ceil | bytes | pkts | drops | overlimits | backlog(B) | backlog(pkts)")
        lines.append("---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:")
        for fname, data in analysis["htb"].items():
            if not data.get("has_htb"):
                lines.append(f"**{fname}** |  |  |  |  |  |  |  |  |  | ")
                continue
            classes = data.get("classes", {})
            if not classes:
                lines.append(f"**{fname}** |  |  |  |  |  |  |  |  |  | ")
            for cid, s in classes.items():
                lines.append(f"{fname}:{cid} | {s.get('parent','')} | {s.get('prio','')} | {s.get('rate','')} | {s.get('ceil','')} | {s.get('bytes','')} | {s.get('packets','')} | {s.get('drops','')} | {s.get('overlimits','')} | {s.get('backlog_bytes','')} | {s.get('backlog_pkts','')}")
    lines.append("")

    # OVS QoS
    lines.append("## Statystyki OVS QoS/queues (opcjonalne)")
    if not analysis.get("qos"):
        lines.append("- brak plików *_qos.txt")
    else:
        lines.append("Plik | queue | packets | bytes | dropped | errors")
        lines.append("---|---:|---:|---:|---:|---:")
        for fname, data in analysis["qos"].items():
            qs = data.get("queues", {})
            if not qs:
                lines.append(f"{fname} |  |  |  |  | ")
            for qid, s in qs.items():
                lines.append(f"{fname} | {qid} | {s.get('packets','')} | {s.get('bytes','')} | {s.get('dropped','')} | {s.get('errors','')}")

    # ogólna uwaga
    lines.append("")
    lines.append(f"**Uwaga**: {checks.get('note','')}")
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

    # CSV 2: queues summary (merge tc + ovs qos into a friendly table)
    with open(out_csv_q, "w", newline="", encoding="utf-8") as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["source_file","iface_or_class","metric","value"])
        # tc
        for fname, data in (analysis.get("htb") or {}).items():
            for cid, s in (data.get("classes") or {}).items():
                for k in ("rate","ceil","bytes","packets","drops","overlimits","backlog_bytes","backlog_pkts"):
                    w.writerow([fname, cid, k, s.get(k,"")])
        # ovs qos
        for fname, data in (analysis.get("qos") or {}).items():
            for qid, s in (data.get("queues") or {}).items():
                for k in ("packets","bytes","dropped","errors"):
                    w.writerow([fname, f"queue{qid}", k, s.get(k,"")])

def main():
    ap = argparse.ArgumentParser(description="Analyze Scenario B: DiffServ + HTB run directory.")
    ap.add_argument("--run-dir", required=True, help="Directory created by run_traffic.py (scenario B)")
    ap.add_argument("--out-dir", default=None, help="Gdzie zapisać raporty; domyślnie do --run-dir")
    args = ap.parse_args()

    analysis = analyze_run(args.run_dir)

    out_dir = args.out_dir or args.run_dir
    os.makedirs(out_dir, exist_ok=True)
    out_md  = os.path.join(out_dir, "diffserv_htb_report.md")
    out_csv_ip = os.path.join(out_dir, "diffserv_summary_rx.csv")
    out_csv_q  = os.path.join(out_dir, "diffserv_queues_summary.csv")
    write_report(analysis, out_md, out_csv_ip, out_csv_q)

    print("OK. Wygenerowano:")
    print(" -", out_md)
    print(" -", out_csv_ip)
    print(" -", out_csv_q)

if __name__ == "__main__":
    main()
