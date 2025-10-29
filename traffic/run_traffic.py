import argparse
import importlib.util
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

# ============================ STAŁE DOMYŚLNE ==================================

BOTTLENECK_DEV_DEFAULT = "s2-eth2"
BOTTLENECK_RATE_DEFAULT = "20mbit"

IPERF_EF_MBIT = 20
IPERF_AF_MBIT = 20
IPERF_BE_MBIT = 20

DSCP_EF = 46
DSCP_AF31 = 26
DSCP_BE = 0

# ============================ POMOCNICZE SH/IO ================================
def sh(cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    """Uruchamia komendę powłoki i zwraca CompletedProcess (stdout w .stdout)."""
    return subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, check=check
    )


def load_topo_from_file(path: str):
    """Ładuje topologię z pliku: preferuje topos['mytopo'], fallback: klasa MyTopo."""
    spec = importlib.util.spec_from_file_location("user_topo", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore
    spec.loader.exec_module(mod)  # type: ignore

    topo = None
    if hasattr(mod, "topos") and isinstance(mod.topos, dict) and "mytopo" in mod.topos:
        topo = mod.topos["mytopo"]()
    elif hasattr(mod, "MyTopo"):
        topo = mod.MyTopo()

    if topo is None:
        raise RuntimeError("Nie znalazłem topologii 'mytopo' ani klasy MyTopo w pliku.")
    return topo


def _timestamp_utc_plus_1() -> str:
    """Zwraca timestamp (UTC+1 bez DST) w formacie YYYYmmdd_HHMMSS."""
    tz_plus1 = timezone(timedelta(hours=1))
    return datetime.now(timezone.utc).astimezone(tz_plus1).strftime("%Y%m%d_%H%M%S")


def make_dirs(base: str, scenario: str) -> Tuple[str, str, str, str, str]:
    """Tworzy katalogi logów i zwraca tuple: (run, clients, servers, switch, pcap)."""
    ts = _timestamp_utc_plus_1()
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


# =========================== MAPOWANIE SCENARIUSZY ============================
def scenario_to_qos_mode(s: str) -> str:
    """A/B/C -> tryb QoS dla kontrolera (ENV QOS_MODE)."""
    s = s.lower()
    if s.startswith("a"):
        return "none"
    if s.startswith("b"):
        # B_HTB -> htb, B_HFSC -> hfsc; brak dopisku -> domyślnie htb
        if "htb" in s:
            return "htb"
        if "hfsc" in s:
            return "hfsc"
        return "htb"
    if s.startswith("c"):
        return "meter"
    return "none"


# ============================ KONFIG OVS/TC ===================================
def clear_ovs_qos(dev: str) -> None:
    """Czyści QoS/Queue na porcie OVS (żeby poprzednie testy nie przeszkadzały)."""
    sh(f"ovs-vsctl -- --if-exists clear port {dev} qos")
    sh("ovs-vsctl -- --all destroy QoS -- --all destroy Queue")


def destroy_tc_root(dev: str) -> None:
    """Usuwa root qdisc (jak istnieje)."""
    sh(f"tc qdisc del dev {dev} root 2>/dev/null")


def apply_tbf(dev: str, rate: str, burst: str = "20kb", latency: str = "50ms") -> None:
    """Ustawia prosty TBF (wąskie gardło) na wskazanym interfejsie."""
    destroy_tc_root(dev)
    sh(f"tc qdisc add dev {dev} root tbf rate {rate} burst {burst} latency {latency}")


def apply_hfsc(dev: str, linkspeed_bits: int, queues: Dict[int, Dict[str, int]]) -> None:
    """Konfiguruje linux-hfsc w OVS: min/max-rate per kolejka (EF/AF/BE)."""
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
        # Dajemy „burst”, żeby UDP nie dławił się przy krótkich bucketach
        burst = lim.get('burst', 150000)  # bytes
        prio = lim.get('priority')
        prio_str = f" other-config:priority={prio}" if prio is not None else ""
        parts.append(
            f"--id=@q{qid} create queue "
            f"other-config:min-rate={lim['min']} "
            f"other-config:max-rate={lim['max']} "
            f"other-config:burst={burst}" + prio_str + " -- "
        )

    cmd = "".join(parts).rstrip(" -- ")
    r = sh(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"OVS HFSC error: {r.stdout}")


def apply_htb(dev: str, queues: Dict[int, Dict[str, int]], linkspeed_bits: int = None) -> None:
    """Konfiguruje linux-htb w OVS: min/max-rate per kolejka (EF/AF/BE)."""
    clear_ovs_qos(dev)

    parts: List[str] = [
        "ovs-vsctl -- ",
        f"set port {dev} qos=@qos -- ",
        "--id=@qos create QoS type=linux-htb ",
    ]
    # Opcjonalny „global cap” (max-rate) na root HTB
    if linkspeed_bits is not None:
        parts[2] = parts[2].rstrip() + f" other-config:max-rate={linkspeed_bits} "
    for qid in sorted(queues.keys()):
        parts.append(f"queues:{qid}=@q{qid} ")
    parts.append("-- ")

    for qid, lim in queues.items():
        burst = lim.get('burst', 150000)  # bytes
        prio = lim.get('priority')
        prio_str = f" other-config:priority={prio}" if prio is not None else ""
        parts.append(
            f"--id=@q{qid} create queue "
            f"other-config:min-rate={lim['min']} "
            f"other-config:max-rate={lim['max']} "
            f"other-config:burst={burst}" + prio_str + " -- "
        )

    cmd = "".join(parts).rstrip(" -- ")
    r = sh(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"OVS HTB error: {r.stdout}")


def add_meters_of13(bridge: str, meters: Dict[int, Dict[str, int]]) -> None:
    """Tworzy metery OF1.3 (band=drop, kbps)"""
    sh(f"ovs-ofctl -O OpenFlow13 del-meters {bridge}")
    for mid, p in meters.items():
        kbps = int(p["rate"] * 1000)
        burst_kb = int(p["burst"] * 1000)
        sh(
            "ovs-ofctl -O OpenFlow13 add-meter "
            f"{bridge} meter={mid},kbps,band=type=drop,rate={kbps},burst_size={burst_kb}"
        )


def dev_to_bridge(dev: str) -> str:
    """Z „s2-eth2” robi „s2” (nazwa bridge’a w OVS)."""
    return dev.split("-")[0]


def disable_offloads(dev: str) -> None:
    """Wyłącza TSO/GSO/GRO/LRO (w Mininecie to zwykle pomaga na powtarzalność)."""
    for c in [
        f"ethtool -K {dev} tso off",
        f"ethtool -K {dev} gso off",
        f"ethtool -K {dev} gro off",
        f"ethtool -K {dev} lro off || true",  # nie wszędzie jest LRO
    ]:
        try:
            sh(c)
        except Exception:
            pass


# ============================ SCENARIUSZE QoS =================================
def setup_qos_for_scenario(scenario: str, bottleneck_dev: str, bottleneck_rate: str) -> str:
    """Ustawia ENV dla kontrolera i konfigurację OVS/TC na porcie wąskiego gardła."""
    mode = scenario_to_qos_mode(scenario)
    os.environ["QOS_MODE"] = mode

    dev = bottleneck_dev
    bridge = dev_to_bridge(dev)

    clear_ovs_qos(dev)
    destroy_tc_root(dev)

    # lepiej wyłączyć offloady na porcie, na którym dławi TBF/kolejki
    try:
        disable_offloads(dev)
    except Exception:
        pass

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
            1: {"rate": 15, "burst": 1},  # EF
            2: {"rate": 5,  "burst": 1},  # AF
            3: {"rate": 20, "burst": 2},  # BE
        }
        add_meters_of13(bridge, meters)
        info(f"[QoS] C/METERS: add-meter na {bridge} (EF=1, AF=2, BE=3)\n")

    elif mode == "htb":
        rate_bits = int(bottleneck_rate.replace("mbit", "")) * 1_000_000
        queues = {
            0: {"min": 1_000_000,  "max": 1_000_000,  "priority": 0, "burst": 150000},  # BE (1 Mbit)
            1: {"min": 4_000_000,  "max": 4_000_000,  "priority": 1, "burst": 200000},  # AF (4 Mbit)
            2: {"min": 15_000_000, "max": 15_000_000, "priority": 2, "burst": 250000},  # EF (15 Mbit)
        }
        apply_htb(dev, queues=queues, linkspeed_bits=rate_bits)
        info(f"[QoS] B/HTB: 3 kolejki na {dev} (EF=2, AF=1, BE=0)\n")

    else:
        info(f"[QoS] Nieznany tryb: {mode} — pomijam\n")

    return mode


# ============================ GENEROWANIE RUCHU ===============================
def start_pcap(ifaces_csv: str, out_dir: str) -> List[int]:
    """Startuje tcpdump (-U, -s 96); zwraca listę PID-ów, żeby można było to ubić."""
    ifaces = [i.strip() for i in ifaces_csv.split(",") if i.strip()]
    pids: List[int] = []
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


def stop_pcap(pids: List[int]) -> None:
    """Wysyła SIGINT do działających tcpdumpów (ładnie się domykają)."""
    for pid in pids:
        sh(f"kill -2 {pid} 2>/dev/null")


def start_iperf_servers(h2, server_dir: str) -> Dict[int, str]:
    """Stawia iperf3 -s na portach 5201/5202/5203 na hoście h2 (log do servers/)."""
    ports = [5201, 5202, 5203]
    for p in ports:
        h2.cmd(f'nohup iperf3 -s -p {p} > {server_dir}/srv_{p}.log 2>&1 &')
    return {5201: "srv_ef.log", 5202: "srv_af31.log", 5203: "srv_be.log"}


def run_iperf_clients(h1, client_dir: str, duration: int) -> None:
    """Odpala iperf3 -u z DSCP (EF/AF31/BE), zapis JSON do clients/."""
    flows = [
        {"name": "ef",   "port": 5201, "mbit": IPERF_EF_MBIT, "dscp": DSCP_EF},
        {"name": "af31", "port": 5202, "mbit": IPERF_AF_MBIT, "dscp": DSCP_AF31},
        {"name": "be",   "port": 5203, "mbit": IPERF_BE_MBIT, "dscp": DSCP_BE},
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
    """Prosty ping (co 0.1s) do h2; zapis do clients/ping.txt."""
    count = max(1, int(duration * 10))
    h1.cmd(f'ping 10.0.0.2 -D -i 0.1 -c {count} > {os.path.join(client_dir, "ping.txt")} 2>&1 &')


# ============================== DIAGNOSTYKA ===================================
def dump_switch_state(switch_dir: str, dump_ports_csv: str) -> None:
    """Zrzuca flowy OVS (s1/s2/s3) + statystyki qdisc/class + ovs-appctl qos/show."""
    for sw in ("s1", "s2", "s3"):
        sh(f'ovs-ofctl -O OpenFlow13 dump-flows {sw} > {os.path.join(switch_dir, f"{sw}_flows.txt")}')
        sh(f'ovs-ofctl show {sw} >> {os.path.join(switch_dir, f"{sw}_flows.txt")}')

    ports = [p.strip() for p in dump_ports_csv.split(",") if p.strip()]
    for dev in ports:
        sh(f'tc -s qdisc show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc.txt")}')
        sh(f'tc -s class show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc_class.txt")}')
        sh(f'ovs-appctl qos/show {dev} > {os.path.join(switch_dir, f"{dev}_qos.txt")}')


def print_dump_flows() -> None:
    """Wypisuje dump-flows dla s1/s2/s3 (na konsole – szybki podgląd)."""
    for sw in ("s1", "s2", "s3"):
        info(f"\n--- dump-flows {sw} ---\n")
        r = sh(f'ovs-ofctl -O OpenFlow13 dump-flows {sw}')
        info(r.stdout if r.stdout else "(brak)\n")


def ping_all_n(net: Mininet, count: int = 1) -> float:
    """Mininet pingAll kilka razy; zwraca uśredniony loss (%)."""
    total_loss = 0.0
    for _ in range(count):
        total_loss += net.pingAll()
    return total_loss / max(1, count)


# ============================== GŁÓWNY PRZEPŁYW ===============================
def main() -> None:
    parser = argparse.ArgumentParser(description="SDN QoS test runner (EF/AF/BE).")
    parser.add_argument("--topo-file", required=True, help="Plik z topologią (MyTopo albo topos['mytopo']).")
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--scenario", required=True, help="A | B | B_HTB | B_HFSC | C")
    parser.add_argument("--log-dir", required=True, help="Gdzie zapisać logi z biegu.")
    parser.add_argument("--dump-ports", default=BOTTLENECK_DEV_DEFAULT, help="CSV interfejsów do zrzutów tc/qos.")
    parser.add_argument("--pcap-ifs", default="", help="CSV interfejsów do tcpdump (opcjonalnie).")
    parser.add_argument("--bottleneck-dev", default=BOTTLENECK_DEV_DEFAULT, help="Interfejs „wąskiego gardła” (np. s2-eth2).")
    parser.add_argument("--bottleneck-rate", default=BOTTLENECK_RATE_DEFAULT, help="Przepływność TBF (np. 20mbit).")
    args = parser.parse_args()

    # Jeżeli użytkownik nie wskazał dump-ports, bierzemy interfejs wąskiego gardła
    if args.dump_ports == BOTTLENECK_DEV_DEFAULT and args.bottleneck_dev != BOTTLENECK_DEV_DEFAULT:
        args.dump_ports = args.bottleneck_dev

    setLogLevel("info")

    # --- start Minineta ---
    topo = load_topo_from_file(args.topo_file)
    net = Mininet(topo=topo, controller=None, link=TCLink, switch=OVSSwitch, cleanup=True)
    c0 = net.addController(name="c0", controller=RemoteController, ip=args.controller_ip, port=args.controller_port)

    info("*** Creating network\n")
    net.start()
    info("*** Starting controller\n")
    c0.start()

    # --- konfiguracja scenariusza (OVS/TC + ENV dla kontrolera) ---
    mode = setup_qos_for_scenario(args.scenario, args.bottleneck_dev, args.bottleneck_rate)

    # --- sanity ping między hostami ---
    h1, h2 = net.get("h1"), net.get("h2")
    info("\n=== Szybki pingAll (sanity) ===\n")
    loss = ping_all_n(net, count=3)
    info(f"PingAll loss ~ {loss}%\n")

    # podgląd flowów „na start”
    print_dump_flows()

    # --- katalogi biegu ---
    run_dir, client_dir, server_dir, switch_dir, pcap_dir = make_dirs(args.log_dir, args.scenario)
    info(f"\n=== Katalog biegu: {run_dir} ===\n")

    # --- tcpdump (opcjonalnie) ---
    pcap_pids: List[int] = []
    if args.pcap_ifs.strip():
        pcap_pids = start_pcap(args.pcap_ifs, pcap_dir)

    # --- ruchek: iperf3 + ping ---
    info("\n=== Start klientów iperf3 ===\n")
    _ = start_iperf_servers(h2, server_dir)
    time.sleep(1.0)

    info(f"  -> EF (DSCP 46, {IPERF_EF_MBIT}M UDP, :5201)")
    info(f"  -> AF31 (DSCP 26, {IPERF_AF_MBIT}M UDP, :5202)")
    info(f"  -> BE (DSCP 0, {IPERF_BE_MBIT}M UDP, :5203)")

    run_iperf_clients(h1, client_dir, args.duration)
    run_ping(h1, client_dir, args.duration)

    # czekamy aż iperfy dojadą
    time.sleep(args.duration + 2)

    # --- zrzuty z OVS/tc ---
    dump_switch_state(switch_dir, args.dump_ports)

    # podgląd flowów „na koniec”
    print_dump_flows()

    # --- meta-info o biegu ---
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

    # --- sprzątanie ---
    if pcap_pids:
        stop_pcap(pcap_pids)

    info("\n=== Sprzątanie iperf3 ===\n")
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    try:
        clear_ovs_qos(args.bottleneck_dev)
        destroy_tc_root(args.bottleneck_dev)
    except Exception:
        pass

    net.stop()
    info(f"\n=== KONIEC. Logi w: {run_dir} ===\n")


# =============================================================================
if __name__ == "__main__":
    main()
