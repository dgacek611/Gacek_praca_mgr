#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import importlib.util
import os
import time
import subprocess
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Dict, List, Tuple, Optional

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

# ========================= USTAWIENIA DOMYŚLNE =========================

BOTTLENECK_DEV_DEFAULT = "s2-eth1"
BOTTLENECK_RATE_DEFAULT = "10mbit"

IPERF_EF_MBIT = 12
IPERF_AF_MBIT = 6
IPERF_BE_MBIT = 2

DSCP_EF = 46
DSCP_AF31 = 26
DSCP_BE = 0

# tylko do meta (kontroler MPLS decyduje)
EXP_EF_DEFAULT = 5
EXP_AF_DEFAULT = 3
EXP_BE_DEFAULT = 0
MPLS_LABEL_DEFAULT = 100

# ========================= NARZĘDZIA POWŁOKI =========================

def sh(cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, check=check)

def _timestamp_utc_plus_1() -> str:
    tz_plus1 = timezone(timedelta(hours=1))
    return datetime.now(timezone.utc).astimezone(tz_plus1).strftime("%Y%m%d_%H%M%S")

def make_dirs(base: str, scenario: str) -> Tuple[str, str, str, str, str]:
    ts = _timestamp_utc_plus_1()
    run_dir = os.path.join(base, f"{scenario}_{ts}")
    client_dir = os.path.join(run_dir, "clients")
    server_dir = os.path.join(run_dir, "servers")
    switch_dir = os.path.join(run_dir, "switch")
    pcap_dir = os.path.join(run_dir, "pcap")
    for d in (client_dir, server_dir, switch_dir, pcap_dir):
        os.makedirs(d, exist_ok=True)
    return run_dir, client_dir, server_dir, switch_dir, pcap_dir

# =========================== TOPOLOGIA ============================

def load_topo_from_file(path: str):
    spec = importlib.util.spec_from_file_location("user_topo", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore
    assert spec and spec.loader, "Nieprawidłowa specyfikacja modułu topologii."
    spec.loader.exec_module(mod)  # type: ignore
    topo = None
    if hasattr(mod, "topos") and isinstance(mod.topos, dict) and "mytopo" in mod.topos:
        topo = mod.topos["mytopo"]()
    elif hasattr(mod, "MyTopo"):
        topo = mod.MyTopo()
    if topo is None:
        raise RuntimeError("Nie znaleziono topologii 'mytopo' ani klasy MyTopo w pliku.")
    return topo

# ============================ OVS/TC ===================================

def clear_ovs_qos(dev: str) -> None:
    sh(f"ovs-vsctl -- --if-exists clear port {dev} qos")
    sh("ovs-vsctl -- --all destroy QoS -- --all destroy Queue")

def destroy_tc_root(dev: str) -> None:
    sh(f"tc qdisc del dev {dev} root 2>/dev/null")

def apply_tbf(dev: str, rate: str, burst: str = "20kb", latency: str = "50ms") -> None:
    destroy_tc_root(dev)
    sh(f"tc qdisc add dev {dev} root tbf rate {rate} burst {burst} latency {latency}")

def apply_hfsc(dev: str, linkspeed_bits: int, queues: Dict[int, Dict[str, int]]) -> None:
    clear_ovs_qos(dev)
    parts: List[str] = [
        "ovs-vsctl -- ",
        f"set port {dev} qos=@qos -- ",
        f"--id=@qos create QoS type=linux-hfsc other-config:linkspeed={linkspeed_bits} ",
    ]
    for qid in sorted(queues.keys()):
        parts.append(f"queues:{qid}=@q{qid} ")
    parts.append("-- ")
    for qid, lim in queues.items():
        burst = lim.get("burst", 150000)
        prio = lim.get("priority")
        prio_str = f" other-config:priority={prio}" if prio is not None else ""
        parts.append(
            f"--id=@q{qid} create queue "
            f"other-config:min-rate={lim['min']} "
            f"other-config:max-rate={lim['max']} "
            f"other-config:burst={burst}{prio_str} -- "
        )
    cmd = "".join(parts).rstrip(" -- ")
    r = sh(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"OVS HFSC error: {r.stdout}")

def apply_htb(dev: str, queues: Dict[int, Dict[str, int]], linkspeed_bits: Optional[int] = None) -> None:
    clear_ovs_qos(dev)
    parts: List[str] = [
        "ovs-vsctl -- ",
        f"set port {dev} qos=@qos -- ",
        "--id=@qos create QoS type=linux-htb ",
    ]
    if linkspeed_bits is not None:
        parts[2] = parts[2].rstrip() + f" other-config:max-rate={linkspeed_bits} "
    for qid in sorted(queues.keys()):
        parts.append(f"queues:{qid}=@q{qid} ")
    parts.append("-- ")
    for qid, lim in queues.items():
        burst = lim.get("burst", 150000)
        prio = lim.get("priority")
        prio_str = f" other-config:priority={prio}" if prio is not None else ""
        parts.append(
            f"--id=@q{qid} create queue "
            f"other-config:min-rate={lim['min']} "
            f"other-config:max-rate={lim['max']} "
            f"other-config:burst={burst}{prio_str} -- "
        )
    cmd = "".join(parts).rstrip(" -- ")
    r = sh(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"OVS HTB error: {r.stdout}")

def dev_to_bridge(dev: str) -> str:
    return dev.split("-")[0]

def disable_offloads(dev: str) -> None:
    for c in [f"ethtool -K {dev} tso off", f"ethtool -K {dev} gso off",
              f"ethtool -K {dev} gro off", f"ethtool -K {dev} lro off || true"]:
        try: sh(c)
        except Exception: pass

# ===== OVS rundir / *.mgmt =====

def find_ovs_rundir(user_hint: Optional[str] = None) -> Optional[str]:
    candidates: List[str] = [user_hint] if user_hint else []
    candidates += ["/var/run/openvswitch", "/run/openvswitch", "/usr/local/var/run/openvswitch"]
    for d in candidates:
        if d and os.path.isdir(d):
            return d
    return None

def wait_mgmt_target(bridge: str, timeout_s: float = 15.0, rundir_hint: Optional[str] = None) -> str:
    import time as _t
    deadline = _t.time() + timeout_s
    last_listing = ""
    while _t.time() < deadline:
        rd = find_ovs_rundir(rundir_hint)
        if rd:
            mgmt = os.path.join(rd, f"{bridge}.mgmt")
            if os.path.exists(mgmt):
                return f"unix:{mgmt}"
            ls = [f for f in os.listdir(rd) if f.endswith(".mgmt")]
            last_listing = " ".join(ls) if ls else "(brak *.mgmt)"
        _t.sleep(0.2)
    raise RuntimeError(f"[OFCTL] Nie znaleziono socketa {bridge}.mgmt.\n{last_listing}")

# ============================ SCENARIUSZE QoS (bez Ryu) ===============================

def scenario_to_qos_mode(s: str) -> str:
    s = s.lower()
    if s.startswith("a"): return "none"
    if s.startswith("b"):
        if "htb" in s: return "htb"
        if "hfsc" in s: return "hfsc"
        return "htb"
    if s.startswith("c"): return "meter"  # tylko obserwujemy/dump (kontroler instaluje metery)
    if s.startswith("d"): return "none"   # MPLS – QoS po naszej stronie: brak
    return "none"

def setup_qos_for_scenario(scenario: str, bottleneck_dev: str, bottleneck_rate: str) -> str:
    mode = scenario_to_qos_mode(scenario)
    dev = bottleneck_dev
    clear_ovs_qos(dev)
    destroy_tc_root(dev)
    try: disable_offloads(dev)
    except Exception: pass

    if mode == "none":
        apply_tbf(dev, bottleneck_rate)
        info(f"[QoS] TBF {bottleneck_rate} na {dev}\n")
    elif mode == "hfsc":
        rate_bits = int(bottleneck_rate.replace("mbit", "")) * 1_000_000
        queues = {
            0: {"min": 1_000_000,  "max": rate_bits},   # BE
            1: {"min": 5_000_000,  "max": rate_bits},   # AF
            2: {"min": 15_000_000, "max": rate_bits},   # EF
        }
        apply_hfsc(dev, linkspeed_bits=rate_bits, queues=queues)
        info(f"[QoS] HFSC na {dev}\n")
    elif mode == "htb":
        rate_bits = int(bottleneck_rate.replace("mbit", "")) * 1_000_000
        queues = {
            0: {"min": 1_000_000,  "max": 1_000_000,  "priority": 0, "burst": 10000},  # BE
            1: {"min": 3_000_000,  "max": 3_000_000,  "priority": 1, "burst": 30000},  # AF
            2: {"min": 6_000_000,  "max": 6_000_000,  "priority": 2, "burst": 60000},  # EF
        }
        apply_htb(dev, queues=queues, linkspeed_bits=rate_bits)
        info(f"[QoS] HTB na {dev}\n")
    elif mode == "meter":
        info("[QoS] METERS: nic nie ustawiamy (kontroler instaluje), my tylko zbierzemy dumpy\n")
    return mode

# ============================ PCAP / GENERATOR RUCHU ===============================

def _canon_ifname(name: str) -> str:
    return name.split('@', 1)[0]

def _iface_exists_root(iface: str) -> bool:
    r = sh("ip -br link")
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        ifname = _canon_ifname(line.split()[0])
        if ifname == iface:
            return True
    print("[PCAP] root ns interfejsy:",
          ", ".join(_canon_ifname(l.split()[0]) for l in r.stdout.splitlines()))
    return False

def _iface_exists_in_host(h, iface: str) -> bool:
    out = h.cmd("ip -br link")
    return any(line.split()[0] == iface for line in out.splitlines())

def start_pcap(net, ifaces_csv: str, out_dir: str, duration_hint: Optional[int] = None) -> List[int]:
    """
    Startuje tcpdump na wielu interfejsach.
    - root ns:  token 's2-eth1' (lub dowolny root IF)
    - host ns:  token 'h1:eth0' (host:ifname)
    Zwraca listę PID-ów tcpdumpów w root ns **i** w host ns (PID procesu tcpdump).
    """
    ifaces = [i.strip() for i in ifaces_csv.split(",") if i.strip()]
    pids: List[int] = []

    for token in ifaces:
        # host namespace?
        if ":" in token:
            host_name, ifname = token.split(":", 1)
            h = net.get(host_name)
            if not _iface_exists_in_host(h, ifname):
                print(f"[PCAP] WARN: {host_name}:{ifname} nie istnieje – pomijam")
                continue
            pcap = os.path.join(out_dir, f"{host_name}_{ifname}.pcap")
            # uruchom tcpdump **w host namespace** (przez h.cmd)
            cmd = f'tcpdump -i {ifname} -w {pcap} -U -s 128 -n "(mpls or ip)" >/dev/null 2>&1 & echo $!'
            pid_str = h.cmd(cmd).strip().splitlines()[-1]
            try:
                pid = int(pid_str)
                pids.append(pid)
                print(f"[PCAP] {host_name}:{ifname} -> pid {pid}")
            except Exception:
                print(f"[PCAP] ERR: nie mogę odczytać PID dla {host_name}:{ifname} (got: {pid_str})")
            continue

        # root namespace (np. s1-eth2, s2-eth1, itp.)
        ifname = token
        if not _iface_exists_root(ifname):
            print(f"[PCAP] WARN: {ifname} nie istnieje (root ns) – pomijam")
            continue
        pcap = os.path.join(out_dir, f"{ifname}.pcap")
        # odpalamy w tle, zapisujemy PID z echo $!
        cmd = f'bash -c \'tcpdump -i {ifname} -w {pcap} -U -s 128 -n "(mpls or ip)" >/dev/null 2>&1 & echo $!\''
        r = sh(cmd)
        try:
            pid = int(r.stdout.strip().splitlines()[-1])
            pids.append(pid)
            print(f"[PCAP] {ifname} (root) -> pid {pid}")
        except Exception:
            print(f"[PCAP] ERR: nie mogę odczytać PID dla {ifname} (got: {r.stdout!r})")
    return pids

def stop_pcap(pids: List[int]) -> None:
    # SIGINT ładnie zamyka pliki PCAP. Jeśli coś nie zginie – SIGKILL po chwili.
    import time as _t
    for pid in pids:
        sh(f"kill -2 {pid} 2>/dev/null")
    _t.sleep(0.5)
    for pid in pids:
        sh(f"kill -0 {pid} 2>/dev/null || true")  # żyje?
        # jeśli żyje – dobij
        sh(f"kill -9 {pid} 2>/dev/null || true")

def start_iperf_servers(h2, server_dir: str) -> Dict[int, str]:
    ports = [5201, 5202, 5203]
    for p in ports:
        h2.cmd(f'nohup iperf3 -s -p {p} > {server_dir}/srv_{p}.log 2>&1 &')
    return {5201: "srv_ef.log", 5202: "srv_af31.log", 5203: "srv_be.log"}

def run_iperf_clients(h1, client_dir: str, duration: int, ef_mbit: int, af_mbit: int, be_mbit: int) -> None:
    flows = [
        {"name": "ef",   "port": 5201, "mbit": ef_mbit, "dscp": DSCP_EF},
        {"name": "af31", "port": 5202, "mbit": af_mbit, "dscp": DSCP_AF31},
        {"name": "be",   "port": 5203, "mbit": be_mbit, "dscp": DSCP_BE},
    ]
    for f in flows:
        tos = f["dscp"] << 2
        out_json = os.path.join(client_dir, f'{f["name"]}.json')
        cmd = (
            f'iperf3 -c 10.0.0.2 -p {f["port"]} -u -b {f["mbit"]}M -t {duration} '
            f'-J --get-server-output --tos {tos} --logfile {out_json} &'
        )
        h1.cmd(cmd)

def run_ping(h1, client_dir: str, duration: int) -> None:
    count = max(1, int(duration * 10))
    h1.cmd(f'ping 10.0.0.2 -D -i 0.1 -c {count} > {os.path.join(client_dir, "ping.txt")} 2>&1 &')

# ============================ DIAGNOSTYKA ===========================

def dump_meters_and_stats(bridge: str, switch_dir: str, rundir_hint: Optional[str] = None) -> None:
    target = wait_mgmt_target(bridge, timeout_s=15.0, rundir_hint=rundir_hint)
    cfg = sh(f"ovs-ofctl -O OpenFlow13 dump-meters {target}").stdout
    st  = sh(f"ovs-ofctl -O OpenFlow13 meter-stats {target}").stdout
    with open(os.path.join(switch_dir, f"{bridge}_meters.txt"), "w") as f:
        f.write("=== dump-meters ===\n")
        f.write(cfg or "(empty)\n")
        f.write("\n=== meter-stats ===\n")
        f.write(st or "(empty)\n")

def dump_switch_state(switch_dir: str, rundir_hint: Optional[str], bridges: List[str], dump_ports_csv: str) -> None:
    for sw in bridges:
        target = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        sh(f'ovs-ofctl -O OpenFlow13 dump-flows {target} > {os.path.join(switch_dir, f"{sw}_flows.txt")}')
        sh(f'ovs-ofctl show {target} >> {os.path.join(switch_dir, f"{sw}_flows.txt")}')
        # tylko podgląd – nic nie tworzymy
        try: dump_meters_and_stats(sw, switch_dir, rundir_hint=rundir_hint)
        except Exception: pass

    ports = [p.strip() for p in dump_ports_csv.split(",") if p.strip()]
    for dev in ports:
        sh(f'tc -s qdisc show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc.txt")}')
        sh(f'tc -s class show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc_class.txt")}')
        sh(f'ovs-appctl qos/show {dev} > {os.path.join(switch_dir, f"{dev}_qos.txt")}')

def print_dump_flows(bridges: List[str], rundir_hint: Optional[str]) -> None:
    for sw in bridges:
        info(f"\n--- dump-flows {sw} ({sw}.mgmt) ---\n")
        target = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        r = sh(f'ovs-ofctl -O OpenFlow13 dump-flows {target}')
        info(r.stdout if r.stdout else "(brak)\n")

def ping_all_n(net: Mininet, count: int = 1) -> float:
    total_loss = 0.0
    for _ in range(count):
        loss = net.pingAll()
        total_loss += loss
    return total_loss / max(1, count)

# ========================= GŁÓWNY PRZEPŁYW =========================

def main() -> None:
    parser = argparse.ArgumentParser(description="SDN QoS/MPLS runner (bez Ryu auto-launch).")
    parser.add_argument("--topo-file", required=True)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--scenario", required=True, help="A|B_htb|B_hfsc|C (meters)|D (MPLS)")
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--dump-ports", default=BOTTLENECK_DEV_DEFAULT)
    parser.add_argument("--pcap-ifs", default="")
    parser.add_argument("--bottleneck-dev", default=BOTTLENECK_DEV_DEFAULT)
    parser.add_argument("--bottleneck-rate", default=BOTTLENECK_RATE_DEFAULT)
    parser.add_argument("--verify-htb", action="store_true")
    parser.add_argument("--ovs-rundir", default="")

    # iperf override
    parser.add_argument("--ef-mbit", type=int, default=IPERF_EF_MBIT)
    parser.add_argument("--af-mbit", type=int, default=IPERF_AF_MBIT)
    parser.add_argument("--be-mbit", type=int, default=IPERF_BE_MBIT)

    # MPLS parametry — tylko do meta (steruje nimi kontroler)
    parser.add_argument("--mpls-mode", default="shortpipe", help="uniform|shortpipe|pipe (meta)")
    parser.add_argument("--mpls-ingress-dpids", default="1", help="np. '1' (meta)")
    parser.add_argument("--mpls-egress-dpids", default="2", help="np. '2' (meta)")
    parser.add_argument("--mpls-exp-ef", type=int, default=EXP_EF_DEFAULT)
    parser.add_argument("--mpls-exp-af", type=int, default=EXP_AF_DEFAULT)
    parser.add_argument("--mpls-exp-be", type=int, default=EXP_BE_DEFAULT)
    parser.add_argument("--mpls-label", type=int, default=MPLS_LABEL_DEFAULT)

    args = parser.parse_args()

    # dopasuj dump-ports do wskazanego bottleneck-dev jeśli zmieniono
    if args.dump_ports == BOTTLENECK_DEV_DEFAULT and args.bottleneck_dev != BOTTLENECK_DEV_DEFAULT:
        args.dump_ports = args.bottleneck_dev

    setLogLevel("info")
    topo = load_topo_from_file(args.topo_file)

    # Start Mininet (bez uruchamiania Ryu)
    net = Mininet(topo=topo, controller=None, link=TCLink,
                  switch=partial(OVSSwitch, protocols="OpenFlow13"), cleanup=True)
    c0 = net.addController(name="c0", controller=RemoteController,
                           ip=args.controller_ip, port=args.controller_port)

    info("*** Creating network\n")
    net.start()

    # poczekaj aż *.mgmt powstaną (żeby dumpy działały)
    rundir_hint = args.ovs_rundir or None
    for sw in ("s1", "s2", "s3"):
        try:
            _ = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        except Exception as e:
            info(f"[WARN] {e}\n")

    # QoS lokalnie (A/B/C/D)
    mode = setup_qos_for_scenario(args.scenario, args.bottleneck_dev, args.bottleneck_rate)

    info("*** Starting controller (połączenie do zewnętrznego Ryu)\n")
    c0.start()

    h1 = net.get("h1")
    h2 = net.get("h2")

    info("\n=== Szybki pingAll (sanity) ===\n")
    loss = ping_all_n(net, count=3)
    info(f"PingAll loss ~ {loss}%\n")

    print_dump_flows(["s1", "s2", "s3"], rundir_hint)

    run_dir, client_dir, server_dir, switch_dir, pcap_dir = make_dirs(args.log_dir, args.scenario)
    info(f"\n=== Katalog biegu: {run_dir} ===\n")

    # PCAP (jeśli nie podano, podpowiadamy sensowne IF-y dla MPLS s1<->s2 + egress do h2)
    if not args.pcap_ifs.strip():
        args.pcap_ifs = "s1-eth2,s2-eth2,s2-eth1"
    pcap_pids = start_pcap(net, args.pcap_ifs, pcap_dir, duration_hint=args.duration)

    # Ruch
    info("\n=== Start iperf3 + ping ===\n")
    _ = start_iperf_servers(h2, server_dir); time.sleep(1.0)
    info(f"  -> EF (DSCP 46, {args.ef_mbit}M, :5201)\n")
    info(f"  -> AF31 (DSCP 26, {args.af_mbit}M, :5202)\n")
    info(f"  -> BE (DSCP 0, {args.be_mbit}M, :5203)\n")
    run_iperf_clients(h1, client_dir, args.duration, args.ef_mbit, args.af_mbit, args.be_mbit)
    run_ping(h1, client_dir, args.duration)

    time.sleep(args.duration + 2)

    # Zrzuty stanów
    dump_switch_state(switch_dir, rundir_hint, ["s1", "s2", "s3"], args.dump_ports)
    print_dump_flows(["s1", "s2", "s3"], rundir_hint)

    # meta
    with open(os.path.join(run_dir, "meta.txt"), "w") as f:
        f.write(f"scenario={args.scenario}\n")
        f.write(f"duration_s={args.duration}\n")
        f.write(f"controller={args.controller_ip}:{args.controller_port}\n")
        f.write("h1_ip=10.0.0.1\nh2_ip=10.0.0.2\n")
        f.write(f"bottleneck_dev={args.bottleneck_dev}\n")
        f.write(f"bottleneck_rate={args.bottleneck_rate}\n")
        f.write(f"qos_mode={mode}\n")
        f.write(f"dump_ports={args.dump_ports}\n")
        f.write(f"pcap_ifs={args.pcap_ifs}\n")

    # Stop PCAP
    if pcap_pids:
        stop_pcap(pcap_pids)

    # Sprzątanie iperf3
    info("\n=== Sprzątanie iperf3 ===\n")
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    # Sprzątanie QoS
    try:
        clear_ovs_qos(args.bottleneck_dev)
        destroy_tc_root(args.bottleneck_dev)
    except Exception:
        pass

    net.stop()
    info(f"\n=== KONIEC. Logi w: {run_dir} ===\n")

if __name__ == "__main__":
    main()
