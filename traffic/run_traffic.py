#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_traffic.py — uruchamia testy EF/AF/BE i zbiera logi.
(…reszta komentarza bez zmian…)
"""

import argparse
import importlib.util
import os
import subprocess
import sys
import time
from datetime import datetime

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

# ========================= USTAWIENIA DOMYŚLNE =========================
BOTTLENECK_DEV_DEFAULT = "s2-eth2"
BOTTLENECK_RATE_DEFAULT = "20mbit"
IPERF_EF_MBIT = 5
IPERF_AF_MBIT = 20
IPERF_BE_MBIT = 50

DSCP_EF = 46
DSCP_AF31 = 26
DSCP_BE = 0

# ========================= NARZĘDZIA POMOCNICZE =========================
def sh(cmd: str, check=False):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=check)

def load_topo_from_file(path):
    spec = importlib.util.spec_from_file_location("user_topo", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    topo = None
    if hasattr(mod, "topos") and isinstance(mod.topos, dict) and "mytopo" in mod.topos:
        topo = mod.topos["mytopo"]()
    elif hasattr(mod, "MyTopo"):
        topo = mod.MyTopo()
    if topo is None:
        raise RuntimeError("Nie znaleziono topologii 'mytopo' ani klasy MyTopo w pliku.")
    return topo

def make_dirs(base, scenario):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir = os.path.join(base, f"{scenario}_{ts}")
    client_dir = os.path.join(run_dir, "clients")
    server_dir = os.path.join(run_dir, "servers")
    switch_dir = os.path.join(run_dir, "switch")
    pcap_dir = os.path.join(run_dir, "pcap")
    os.makedirs(client_dir, exist_ok=True)
    os.makedirs(server_dir, exist_ok=True)
    os.makedirs(switch_dir, exist_ok=True)
    os.makedirs(pcap_dir, exist_ok=True)
    return run_dir, client_dir, server_dir, switch_dir, pcap_dir

def scenario_to_qos_mode(s: str) -> str:
    s = s.lower()
    if s.startswith("a"):
        return "none"
    if s.startswith("b"):
        return "hfsc"
    if s.startswith("c"):
        return "meter"
    return "none"

def clear_ovs_qos(dev: str):
    sh(f"ovs-vsctl -- --if-exists clear port {dev} qos")
    sh("ovs-vsctl -- --all destroy QoS -- --all destroy Queue")

def destroy_tc_root(dev: str):
    sh(f"tc qdisc del dev {dev} root 2>/dev/null")

def apply_tbf(dev: str, rate: str, burst="20kb", latency="50ms"):
    destroy_tc_root(dev)
    sh(f"tc qdisc add dev {dev} root tbf rate {rate} burst {burst} latency {latency}")

def apply_hfsc(dev: str, linkspeed_bits: int, queues):
    clear_ovs_qos(dev)
    parts = [
        "ovs-vsctl -- ",
        f"set port {dev} qos=@qos -- ",
        f"--id=@qos create QoS type=linux-hfsc other-config:linkspeed={linkspeed_bits} "
    ]
    for qid in sorted(queues.keys()):
        parts.append(f"queues:{qid}=@q{qid} ")
    parts.append("-- ")
    for qid, lim in queues.items():
        parts.append(f"--id=@q{qid} create queue other-config:min-rate={lim['min']} other-config:max-rate={lim['max']} -- ")
    cmd = "".join(parts).rstrip(" -- ")
    r = sh(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"OVS HFSC error: {r.stdout}")

def add_meters_of13(bridge: str, meters):
    sh(f"ovs-ofctl -O OpenFlow13 del-meters {bridge}")
    for mid, p in meters.items():
        kbps = int(p["rate"] * 1000)
        burst_kb = int(p["burst"] * 1000)
        sh(f"ovs-ofctl -O OpenFlow13 add-meter {bridge} meter={mid},kbps,band=type=drop,rate={kbps},burst_size={burst_kb}")

def dev_to_bridge(dev: str) -> str:
    return dev.split("-")[0]

def setup_qos_for_scenario(scenario: str, bottleneck_dev: str, bottleneck_rate: str):
    mode = scenario_to_qos_mode(scenario)
    os.environ["QOS_MODE"] = mode

    dev = bottleneck_dev
    bridge = dev_to_bridge(dev)

    clear_ovs_qos(dev)
    destroy_tc_root(dev)

    if mode == "none":
        apply_tbf(dev, bottleneck_rate)
        info(f"[QoS] A/Baseline: TBF {bottleneck_rate} na {dev}\n")
    elif mode == "hfsc":
        rate_bits = int(bottleneck_rate.replace("mbit", "")) * 1_000_000
        queues = {
            0: {"min": 1_000_000,  "max": rate_bits},   # BE
            1: {"min": 5_000_000,  "max": rate_bits},   # AF
            2: {"min": 15_000_000, "max": rate_bits},   # EF
        }
        apply_hfsc(dev, linkspeed_bits=rate_bits, queues=queues)
        info(f"[QoS] B/HFSC: 3 kolejki na {dev} (EF=2, AF=1, BE=0)\n")
    elif mode == "meter":
        meters = {
            1: {"rate": 15, "burst": 1},   # EF
            2: {"rate":  5, "burst": 1},   # AF
            3: {"rate": 20, "burst": 2},   # BE
        }
        add_meters_of13(bridge, meters)
        info(f"[QoS] C/METERS: add-meter na {bridge} (EF=1, AF=2, BE=3)\n")
    else:
        info(f"[QoS] Nieznany tryb: {mode} — pomijam\n")

    return mode

def start_pcap(ifaces_csv: str, out_dir: str):
    ifaces = [i.strip() for i in ifaces_csv.split(",") if i.strip()]
    pids = []
    for iface in ifaces:
        pcap = os.path.join(out_dir, f"{iface}.pcap")
        cmd = f"tcpdump -i {iface} -w {pcap} -U -s 96 not arp and not icmp & echo $!"
        r = sh(cmd)
        try:
            pid = int(r.stdout.strip().splitlines()[-1])
            pids.append(pid)
        except Exception:
            pass
    return pids

def stop_pcap(pids):
    for pid in pids:
        sh(f"kill -2 {pid} 2>/dev/null")

def start_iperf_servers(h2, server_dir):
    ports = [5201, 5202, 5203]
    for p in ports:
        h2.cmd(f'nohup iperf3 -s -p {p} > {server_dir}/srv_{p}.log 2>&1 &')
    return {5201: "srv_ef.log", 5202: "srv_af31.log", 5203: "srv_be.log"}

def run_iperf_clients(h1, client_dir, duration):
    flows = [
        {"name": "ef",   "port": 5201, "mbit": IPERF_EF_MBIT,  "dscp": DSCP_EF},
        {"name": "af31", "port": 5202, "mbit": IPERF_AF_MBIT,  "dscp": DSCP_AF31},
        {"name": "be",   "port": 5203, "mbit": IPERF_BE_MBIT,  "dscp": DSCP_BE},
    ]
    for f in flows:
        tos = f["dscp"] << 2
        out_json = os.path.join(client_dir, f'{f["name"]}.json')
        cmd = (
            f'iperf3 -c 10.0.0.2 -p {f["port"]} -u -b {f["mbit"]}M -t {duration} '
            f'-J --get-server-output --tos {tos} --logfile {out_json} &'
        )
        h1.cmd(cmd)

def run_ping(h1, client_dir, duration):
    count = max(1, int(duration * 10))
    h1.cmd(f'ping 10.0.0.2 -D -i 0.1 -c {count} > {os.path.join(client_dir, "ping.txt")} 2>&1 &')

def dump_switch_state(switch_dir, dump_ports_csv):
    for sw in ("s1", "s2", "s3"):
        sh(f'ovs-ofctl -O OpenFlow13 dump-flows {sw} > {os.path.join(switch_dir, f"{sw}_flows.txt")}')
        sh(f'ovs-ofctl show {sw} >> {os.path.join(switch_dir, f"{sw}_flows.txt")}')
    ports = [p.strip() for p in dump_ports_csv.split(",") if p.strip()]
    for dev in ports:
        sh(f'tc -s qdisc show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc.txt")}')
        sh(f'tc -s class show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc_class.txt")}')

def print_dump_flows():
    """Pomocniczy podgląd dump-flows w konsoli."""
    for sw in ("s1", "s2", "s3"):
        info(f"\n--- dump-flows {sw} ---\n")
        r = sh(f'ovs-ofctl -O OpenFlow13 dump-flows {sw}')
        info(r.stdout if r.stdout else "(brak)\n")

def ping_all_n(net, count=1):
    total_loss = 0.0
    for _ in range(count):
        loss = net.pingAll()
        total_loss += loss
    return total_loss / max(1, count)

# ========================= GŁÓWNY PRZEPŁYW =========================
def main():
    parser = argparse.ArgumentParser(description="SDN QoS test runner (EF/AF/BE).")
    parser.add_argument("--topo-file", required=True)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--dump-ports", default=BOTTLENECK_DEV_DEFAULT)
    parser.add_argument("--pcap-ifs", default="")
    parser.add_argument("--bottleneck-dev", default=BOTTLENECK_DEV_DEFAULT)
    parser.add_argument("--bottleneck-rate", default=BOTTLENECK_RATE_DEFAULT)
    args = parser.parse_args()

    setLogLevel('info')

    topo = load_topo_from_file(args.topo_file)

    net = Mininet(
        topo=topo,
        controller=None,
        link=TCLink,
        switch=OVSSwitch,
        cleanup=True
    )
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip=args.controller_ip,
        port=args.controller_port
    )

    info('*** Creating network\n')
    net.start()
    info('*** Starting controller\n')
    c0.start()

    mode = setup_qos_for_scenario(args.scenario, args.bottleneck_dev, args.bottleneck_rate)

    h1 = net.get('h1')
    h2 = net.get('h2')

    info('\n=== Szybki pingAll (sanity) ===\n')
    loss = ping_all_n(net, count=3)
    info(f'PingAll loss ~ {loss}%\n')

    # >>> PODGLĄD FLOWÓW PO STARCIU <<<
    print_dump_flows()

    run_dir, client_dir, server_dir, switch_dir, pcap_dir = make_dirs(args.log_dir, args.scenario)
    info(f'\n=== Katalog biegu: {run_dir} ===\n')

    pcap_pids = []
    if args.pcap_ifs.strip():
        pcap_pids = start_pcap(args.pcap_ifs, pcap_dir)

    info('\n=== Start klientów iperf3 ===\n')
    srv_map = start_iperf_servers(h2, server_dir)
    time.sleep(1.0)

    info('  -> EF (DSCP 46, 5M UDP, :5201)\n')
    info('  -> AF31 (DSCP 26, 20M UDP, :5202)\n')
    info('  -> BE (DSCP 0, 50M UDP, :5203)\n')
    run_iperf_clients(h1, client_dir, args.duration)
    run_ping(h1, client_dir, args.duration)

    time.sleep(args.duration + 2)

    dump_switch_state(switch_dir, args.dump_ports)

    # >>> PODGLĄD FLOWÓW NA KONIEC BIEGU <<<
    print_dump_flows()

    with open(os.path.join(run_dir, "meta.txt"), "w") as f:
        f.write(f'scenario={args.scenario}\n')
        f.write(f'duration_s={args.duration}\n')
        f.write(f'controller={args.controller_ip}:{args.controller_port}\n')
        f.write('h1_ip=10.0.0.1\nh2_ip=10.0.0.2\n')
        f.write(f'bottleneck_dev={args.bottleneck_dev}\n')
        f.write(f'bottleneck_rate={args.bottleneck_rate}\n')
        f.write(f'qos_mode={mode}\n')
        f.write(f'dump_ports={args.dump_ports}\n')
        f.write(f'pcap_ifs={args.pcap_ifs}\n')

    if pcap_pids:
        stop_pcap(pcap_pids)

    info('\n=== Sprzątanie iperf3 ===\n')
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    try:
        clear_ovs_qos(args.bottleneck_dev)
        destroy_tc_root(args.bottleneck_dev)
    except Exception:
        pass

    net.stop()
    info(f'\n=== KONIEC. Logi w: {run_dir} ===\n')


if __name__ == '__main__':
    main()
