import argparse
import importlib.util
import os
import signal
import subprocess
import time
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

IPERF_EF_MBIT = 6
IPERF_AF_MBIT = 6
IPERF_BE_MBIT = 6

DSCP_EF = 46
DSCP_AF31 = 26
DSCP_BE = 0


# ========================= NARZĘDZIA POMOCNICZE =========================

def sh(cmd: str, check: bool = False, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """Uruchamia komendę powłoki i zwraca wynik (stdout+stderr)."""
    return subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=check,
        env=env,
    )


def popen(cmd: List[str], env: Optional[Dict[str, str]] = None) -> subprocess.Popen:
    """Uruchamia proces w tle (np. ryu-manager) i zwraca uchwyt."""
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )


def load_topo_from_file(path: str):
    """
    Ładuje topologię z pliku Python:
      - topos['mytopo']() albo
      - klasa MyTopo()
    """
    spec = importlib.util.spec_from_file_location("user_topo", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[assignment]
    assert spec and spec.loader, "Nieprawidłowa specyfikacja modułu topologii."
    spec.loader.exec_module(mod)  # type: ignore[arg-type]

    topo = None
    if hasattr(mod, "topos") and isinstance(mod.topos, dict) and "mytopo" in mod.topos:
        topo = mod.topos["mytopo"]()
    elif hasattr(mod, "MyTopo"):
        topo = mod.MyTopo()

    if topo is None:
        raise RuntimeError("Nie znaleziono topologii 'mytopo' ani klasy MyTopo w pliku.")
    return topo


def _timestamp_utc_plus_1() -> str:
    """Zwraca timestamp (UTC+1 bez DST) w formacie YYYYmmdd_HHMMSS."""
    tz_plus1 = timezone(timedelta(hours=1))
    return datetime.now(timezone.utc).astimezone(tz_plus1).strftime("%Y%m%d_%H%M%S")


def make_dirs(base: str, scenario: str) -> Tuple[str, str, str, str, str]:
    """Tworzy katalogi logów. Zwraca: (run, clients, servers, switch, pcap)."""
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
    """Czyści QoS/Queue na porcie OVS."""
    sh(f"ovs-vsctl -- --if-exists clear port {dev} qos")
    sh("ovs-vsctl -- --all destroy QoS -- --all destroy Queue")


def destroy_tc_root(dev: str) -> None:
    """Usuwa root qdisc (jeśli istnieje)."""
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
    """Konfiguruje linux-htb w OVS: min/max-rate per kolejka (EF/AF/BE)."""
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
    """Z „s2-eth2” robi „s2” (nazwa bridge’a w OVS)."""
    return dev.split("-")[0]


def disable_offloads(dev: str) -> None:
    """Wyłącza TSO/GSO/GRO/LRO na interfejsie (jeśli dostępne)."""
    cmds = [
        f"ethtool -K {dev} tso off",
        f"ethtool -K {dev} gso off",
        f"ethtool -K {dev} gro off",
        f"ethtool -K {dev} lro off || true",
    ]
    for c in cmds:
        try:
            sh(c)
        except Exception:
            pass


# ===== Pomoc do *.mgmt (unix:/var/run/openvswitch/sX.mgmt) =====

def find_ovs_rundir(user_hint: Optional[str] = None) -> Optional[str]:
    """Zwraca katalog rundir OVS (na podstawie podpowiedzi lub typowych lokalizacji)."""
    candidates: List[str] = []
    if user_hint:
        candidates.append(user_hint)
    candidates += [
        "/var/run/openvswitch",
        "/run/openvswitch",
        "/usr/local/var/run/openvswitch",
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return None


def wait_mgmt_target(bridge: str, timeout_s: float = 15.0, rundir_hint: Optional[str] = None) -> str:
    """
    Czeka aż pojawi się gniazdo management dla bridge’a (np. s2 -> s2.mgmt).
    Zwraca "unix:/.../s2.mgmt".
    """
    deadline = time.time() + timeout_s
    last_listing = ""

    while time.time() < deadline:
        rd = find_ovs_rundir(rundir_hint)
        if rd:
            mgmt = os.path.join(rd, f"{bridge}.mgmt")
            if os.path.exists(mgmt):
                return f"unix:{mgmt}"
            # debug listing
            ls = [f for f in os.listdir(rd) if f.endswith(".mgmt")]
            last_listing = " ".join(ls) if ls else "(brak *.mgmt)"
        time.sleep(0.2)

    raise RuntimeError(
        f"[OFCTL] Nie znaleziono socketa {bridge}.mgmt w typowych rundirach.\n"
        f"/var/run/openvswitch|/run/openvswitch|/usr/local/var/run/openvswitch:\n{last_listing}"
    )


# ===== METERS: tylko weryfikacja/dump przez ofctl (kontroler wstrzykuje metery) =====

def dump_meters_and_stats(bridge: str, switch_dir: str, rundir_hint: Optional[str] = None) -> None:
    """Zrzuca konfigurację i statystyki meterów do plików w switch_dir."""
    target = wait_mgmt_target(bridge, timeout_s=15.0, rundir_hint=rundir_hint)
    cfg = sh(f"ovs-ofctl -O OpenFlow13 dump-meters {target}").stdout
    st = sh(f"ovs-ofctl -O OpenFlow13 meter-stats {target}").stdout
    with open(os.path.join(switch_dir, f"{bridge}_meters.txt"), "w") as f:
        f.write("=== dump-meters ===\n")
        f.write(cfg or "(empty)\n")
        f.write("\n=== meter-stats ===\n")
        f.write(st or "(empty)\n")


def assert_meters_present(bridge: str, expected_ids: List[int], rundir_hint: Optional[str] = None) -> None:
    """Sprawdza obecność oczekiwanych meterów na bridge’u."""
    target = wait_mgmt_target(bridge, timeout_s=15.0, rundir_hint=rundir_hint)
    out = sh(f"ovs-ofctl -O OpenFlow13 dump-meters {target}").stdout
    missing = [mid for mid in expected_ids if f"meter={mid}" not in out]
    if missing:
        raise RuntimeError(f"[METERS] Na {bridge} brakuje meterów {missing}.\nDump:\n{out}")


# ============================ SCENARIUSZE QoS =================================

def setup_qos_for_scenario(scenario: str, bottleneck_dev: str, bottleneck_rate: str) -> str:
    """Ustawia ENV dla kontrolera i konfigurację OVS/TC na porcie wąskiego gardła."""
    mode = scenario_to_qos_mode(scenario)
    os.environ["QOS_MODE"] = mode  # tylko informacyjnie (nie wpływa na już uruchomiony Ryu)

    dev = bottleneck_dev
    clear_ovs_qos(dev)
    destroy_tc_root(dev)

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
        # Metery doinstaluje kontroler Ryu (qos_ryu.py); my tylko dump/weryfikacja po starcie.
        info("[QoS] C/METERS: przygotowanie pod metry (kontroler zainstaluje OF meters)\n")

    elif mode == "htb":
        rate_bits = int(bottleneck_rate.replace("mbit", "")) * 1_000_000
        queues = {
            0: {"min": 1_000_000,  "max": 1_000_000,  "priority": 0, "burst": 10000},  # BE
            1: {"min": 3_000_000,  "max": 3_000_000,  "priority": 1, "burst": 30000},  # AF
            2: {"min": 6_000_000, "max": 6_000_000, "priority": 2, "burst": 60000},  # EF
        }
        apply_htb(dev, queues=queues, linkspeed_bits=rate_bits)
        info(f"[QoS] B/HTB: 3 kolejki na {dev} (EF=2, AF=1, BE=0)\n")

    else:
        info(f"[QoS] Nieznany tryb: {mode} — pomijam\n")

    return mode


# ============================ GENEROWANIE RUCHU ===============================

def start_pcap(ifaces_csv: str, out_dir: str) -> List[int]:
    """Startuje tcpdump (-U, -s 96) i zwraca listę PID-ów do późniejszego zakończenia."""
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


def run_iperf_clients(h1, client_dir: str, duration: int,
                      ef_mbit: int, af_mbit: int, be_mbit: int) -> None:
    """Uruchamia klientów iperf3 na h1 dla EF/AF/BE (UDP, DSCP)."""
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
    """Odpala pomiar RTT pingi co 100 ms (czas = duration)."""
    count = max(1, int(duration * 10))
    h1.cmd(f'ping 10.0.0.2 -D -i 0.1 -c {count} > {os.path.join(client_dir, "ping.txt")} 2>&1 &')


# ============================ DIAGNOSTYKA ===========================

def dump_switch_state(switch_dir: str, rundir_hint: Optional[str], bridges: List[str], dump_ports_csv: str) -> None:
    """Zrzuca flows (po unix sockecie) i qdisc/class dla wybranych portów + meter stats."""
    for sw in bridges:
        target = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        sh(f'ovs-ofctl -O OpenFlow13 dump-flows {target} > {os.path.join(switch_dir, f"{sw}_flows.txt")}')
        sh(f'ovs-ofctl show {target} >> {os.path.join(switch_dir, f"{sw}_flows.txt")}')
        dump_meters_and_stats(sw, switch_dir, rundir_hint=rundir_hint)

    ports = [p.strip() for p in dump_ports_csv.split(",") if p.strip()]
    for dev in ports:
        sh(f'tc -s qdisc show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc.txt")}')
        sh(f'tc -s class show dev {dev} > {os.path.join(switch_dir, f"{dev}_tc_class.txt")}')
        sh(f'ovs-appctl qos/show {dev} > {os.path.join(switch_dir, f"{dev}_qos.txt")}')


def print_dump_flows(bridges: List[str], rundir_hint: Optional[str]) -> None:
    """Wypisuje dump-flows dla wybranych bridge’y (na stdout Minineta)."""
    for sw in bridges:
        info(f"\n--- dump-flows {sw} ({sw}.mgmt) ---\n")
        target = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        r = sh(f'ovs-ofctl -O OpenFlow13 dump-flows {target}')
        info(r.stdout if r.stdout else "(brak)\n")


def ping_all_n(net: Mininet, count: int = 1) -> float:
    """Uruchamia pingAll count razy i zwraca średni loss (%)."""
    total_loss = 0.0
    for _ in range(count):
        loss = net.pingAll()
        total_loss += loss
    return total_loss / max(1, count)


# ========================= GŁÓWNY PRZEPŁYW =========================

def main() -> None:
    parser = argparse.ArgumentParser(description="SDN QoS test runner (EF/AF/BE).")
    parser.add_argument("--topo-file", required=True)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--scenario", required=True, help="A|B_htb|B_hfsc|C (meters)")
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--dump-ports", default=BOTTLENECK_DEV_DEFAULT)
    parser.add_argument("--pcap-ifs", default="")
    parser.add_argument("--bottleneck-dev", default=BOTTLENECK_DEV_DEFAULT)
    parser.add_argument("--bottleneck-rate", default=BOTTLENECK_RATE_DEFAULT)
    parser.add_argument("--verify-htb", action="store_true")

    # Iperf override
    parser.add_argument("--ef-mbit", type=int, default=IPERF_EF_MBIT)
    parser.add_argument("--af-mbit", type=int, default=IPERF_AF_MBIT)
    parser.add_argument("--be-mbit", type=int, default=IPERF_BE_MBIT)

    # Ryu auto-launch (opcjonalne)
    parser.add_argument("--launch-ryu", default="", help="Ścieżka do qos_ryu.py. Jeśli podane, skrypt wystartuje Ryu.")
    parser.add_argument("--ryu-extra", default="", help="Dodatkowe argumenty do ryu-manager (opcjonalne).")
    parser.add_argument("--meter-dpids", default="2", help="DPID-y (np. '2,3') dla QOS_METER_DPIDS przy auto-launch Ryu.")
    parser.add_argument("--ovs-rundir", default="", help="Wymuszenie ścieżki z *.mgmt, jeśli różna niż standardowa.")

    args = parser.parse_args()

    # Jeżeli użytkownik nie wskazał dump-ports, użyj interfejsu wąskiego gardła
    if args.dump_ports == BOTTLENECK_DEV_DEFAULT and args.bottleneck_dev != BOTTLENECK_DEV_DEFAULT:
        args.dump_ports = args.bottleneck_dev

    setLogLevel("info")

    topo = load_topo_from_file(args.topo_file)

    # (Opcjonalnie) odpal Ryu z ENV (dla scenariusza C dobieram automatycznie QOS_MODE/QOS_METER_DPIDS)
    ryu_proc: Optional[subprocess.Popen] = None
    if args.launch_ryu:
        env = os.environ.copy()
        qos_mode = scenario_to_qos_mode(args.scenario)
        env["QOS_MODE"] = qos_mode

        # Przekaż limity dla meterów (przydadzą się w qos_ryu.py)
        env["QOS_EF_MBIT"] = str(args.ef_mbit)
        env["QOS_AF_MBIT"] = str(args.af_mbit)
        env["QOS_BE_MBIT"] = str(args.be_mbit)

        # Domyślne bursty
        env.setdefault("QOS_EF_BURST_MB", "1")
        env.setdefault("QOS_AF_BURST_MB", "1")
        env.setdefault("QOS_BE_BURST_MB", "2")

        # Jeśli to meters (C), ustaw domyślnie DPID-y (chyba, że podano inaczej)
        env["QOS_METER_DPIDS"] = args.meter_dpids if qos_mode == "meter" else ""

        cmd = [
            "ryu-manager",
            "--verbose",
            "--ofp-tcp-listen-port", str(args.controller_port),
            args.launch_ryu,
        ]
        if args.ryu_extra.strip():
            cmd.extend(args.ryu_extra.strip().split())

        info(f"*** Launch Ryu: {' '.join(cmd)} (QOS_MODE={env['QOS_MODE']}, QOS_METER_DPIDS={env.get('QOS_METER_DPIDS','')})\n")
        ryu_proc = popen(cmd, env=env)

        # Daj krótką chwilę, żeby Ryu wstał
        time.sleep(1.0)

    # Start Minineta (user datapath + OF13, żeby mieć *.mgmt)
    net = Mininet(
        topo=topo,
        controller=None,
        link=TCLink,
        switch=partial(OVSSwitch, protocols="OpenFlow13"),
        cleanup=True,
    )
    c0 = net.addController(
        name="c0",
        controller=RemoteController,
        ip=args.controller_ip,
        port=args.controller_port,
    )

    info("*** Creating network\n")
    net.start()

    # Upewnij się, że *.mgmt już istnieją zanim pójdą dumpy
    rundir_hint = args.ovs_rundir or None
    for sw in ("s1", "s2", "s3"):
        try:
            _ = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        except Exception as e:
            info(f"[WARN] {e}\n")

    # QoS (TBF/HTB/HFSC/meters)
    mode = setup_qos_for_scenario(args.scenario, args.bottleneck_dev, args.bottleneck_rate)

    info("*** Starting controller\n")
    c0.start()

    # Hosty
    h1 = net.get("h1")
    h2 = net.get("h2")

    info("\n=== Szybki pingAll (sanity) ===\n")
    loss = ping_all_n(net, count=3)
    info(f"PingAll loss ~ {loss}%\n")

    # Podgląd (po sockecie)
    print_dump_flows(["s1", "s2", "s3"], rundir_hint)

    run_dir, client_dir, server_dir, switch_dir, pcap_dir = make_dirs(args.log_dir, args.scenario)
    info(f"\n=== Katalog biegu: {run_dir} ===\n")

    # meters: daj Ryu chwilę na instalację meterów + reguł i zweryfikuj
    if mode == "meter":
        info("[VERIFY] Oczekiwanie na instalację meterów przez kontroler...\n")
        time.sleep(1.0)  # krótki oddech, żeby uniknąć ścigania się

        # Zweryfikuj metery na s2 (i ewentualnie s3, jeśli podałeś w --meter-dpids)
        meter_dpids = [p.strip() for p in (os.environ.get("QOS_METER_DPIDS") or args.meter_dpids).split(",") if p.strip()]

        # mapowanie dpid->bridge name
        bridges: List[str] = []
        for d in meter_dpids:
            try:
                n = int(d)
                bridges.append(f"s{n}")
            except Exception:
                pass

        if not bridges:
            bridges = ["s2"]  # domyślnie s2

        # sprawdź, czy metery są
        for br in bridges:
            try:
                assert_meters_present(br, [1, 2, 3], rundir_hint=rundir_hint)
                info(f"[VERIFY] {br}: metery 1,2,3 obecne.\n")
            except Exception as e:
                info(f"[WARN] {br}: {e}\n")

    # (opcjonalnie) HTB weryfikacja
    if args.verify_htb and mode == "htb":
        info(f"[VERIFY] Sprawdzam czy HTB jest faktycznie nałożony na {args.bottleneck_dev}\n")
        # Prosta heurystyka: zrzucamy qdisc/class do switch_dir
        sh(f'tc -s qdisc show dev {args.bottleneck_dev} > {os.path.join(switch_dir, "htb_qdisc.txt")}')
        sh(f'tc -s class show dev {args.bottleneck_dev} > {os.path.join(switch_dir, "htb_class.txt")}')
        sh(f'ovs-appctl qos/show {args.bottleneck_dev} > {os.path.join(switch_dir, "htb_qos.txt")}')

    # (opcjonalnie) PCAP
    pcap_pids: List[int] = []
    if args.pcap_ifs.strip():
        pcap_pids = start_pcap(args.pcap_ifs, pcap_dir)

    # Generowanie ruchu
    info("\n=== Start klientów iperf3 ===\n")
    _ = start_iperf_servers(h2, server_dir)
    time.sleep(1.0)

    info(f"  -> EF (DSCP 46, {args.ef_mbit}M UDP, :5201)\n")
    info(f"  -> AF31 (DSCP 26, {args.af_mbit}M UDP, :5202)\n")
    info(f"  -> BE (DSCP 0, {args.be_mbit}M UDP, :5203)\n")

    run_iperf_clients(h1, client_dir, args.duration, args.ef_mbit, args.af_mbit, args.be_mbit)
    run_ping(h1, client_dir, args.duration)

    time.sleep(args.duration + 2)

    # Zrzuty (flows + meter stats po sockecie)
    dump_switch_state(switch_dir, rundir_hint, ["s1", "s2", "s3"], args.dump_ports)

    # Podgląd flowów na koniec
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

    # Stop PCAP (jeśli było)
    if pcap_pids:
        stop_pcap(pcap_pids)

    # Sprzątanie iperf3
    info("\n=== Sprzątanie iperf3 ===\n")
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    # Sprzątanie QoS/TC
    try:
        clear_ovs_qos(args.bottleneck_dev)
        destroy_tc_root(args.bottleneck_dev)
    except Exception:
        pass

    # Stop Mininet
    net.stop()

    # Zamknij ewentualnego Ryu
    if ryu_proc:
        try:
            ryu_proc.send_signal(signal.SIGINT)
            ryu_proc.wait(timeout=3)
        except Exception:
            ryu_proc.kill()

    info(f"\n=== KONIEC. Logi w: {run_dir} ===\n")


if __name__ == "__main__":
    main()
