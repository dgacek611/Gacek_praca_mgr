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


# Domyślne urządzenie będące „wąskim gardłem” (uplink providera sp1)
BOTTLENECK_DEV_DEFAULT = "sp1-eth2"

# Domyślne szybkości strumieni iperf3 (w Mbit/s)
IPERF_EF_MBIT = 40
IPERF_AF_MBIT = 40
IPERF_BE_MBIT = 40

# Wartości DSCP użyte w eksperymencie
DSCP_EF = 46
DSCP_AF31 = 26
DSCP_BE = 0


# ---------- shell helpers ----------

def sh(
    cmd: str,
    check: bool = False,
    env: Optional[Dict[str, str]] = None
) -> subprocess.CompletedProcess:
    """
    Uruchamia polecenie powłoki i zwraca CompletedProcess.

    cmd   – komenda w formie stringa (shell=True),
    check – jeśli True, subprocess.run podniesie wyjątek przy != 0,
    env   – opcjonalne nadpisanie środowiska.
    """
    return subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=check,
        env=env,
    )


def popen(
    cmd: List[str],
    env: Optional[Dict[str, str]] = None
) -> subprocess.Popen:
    """
    Uruchamia proces w tle (Popen) z przekierowanym stdout/stderr.
    """
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )


# ---------- topo loader ----------

def load_topo_from_file(path: str):
    """
    Ładuje topologię Mininet z pliku .py:
    - szuka słownika `topos` (klasy pod kluczami 'polska'/'mytopo' lub jedyny wpis),
    - alternatywnie klas `PolskaTopo` / `MyTopo`.
    """
    spec = importlib.util.spec_from_file_location("user_topo", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[assignment]
    assert spec and spec.loader, "Nieprawidłowa specyfikacja modułu topologii."
    spec.loader.exec_module(mod)  # type: ignore[arg-type]

    topo = None

    # Najpierw podejście z `topos`
    if hasattr(mod, "topos") and isinstance(mod.topos, dict) and mod.topos:
        if "polska" in mod.topos:
            topo = mod.topos["polska"]()
        elif "mytopo" in mod.topos:
            topo = mod.topos["mytopo"]()
        elif len(mod.topos) == 1:
            topo = next(iter(mod.topos.values()))()

    # Alternatywnie: klasy o standardowych nazwach
    if topo is None and hasattr(mod, "PolskaTopo"):
        topo = mod.PolskaTopo()
    if topo is None and hasattr(mod, "MyTopo"):
        topo = mod.MyTopo()

    if topo is None:
        raise RuntimeError("Nie znaleziono topologii.")
    return topo


# ---------- dirs & ts ----------

def _timestamp_utc_plus_1() -> str:
    """
    Zwraca timestamp (YYYYMMDD_HHMMSS) w strefie UTC+1.
    """
    tz_plus1 = timezone(timedelta(hours=1))
    return datetime.now(timezone.utc).astimezone(tz_plus1).strftime("%Y%m%d_%H%M%S")


def make_dirs(base: str, scenario: str) -> Tuple[str, str, str, str, str]:
    """
    Tworzy katalog biegu:
      base/scenariusz_timestamp/
        - clients
        - servers
        - switch
        - pcap
    Zwraca krotkę: (run_dir, client_dir, server_dir, switch_dir, pcap_dir).
    """
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


# ---------- scenario mapping ----------

def scenario_to_qos_mode(s: str) -> str:
    """
    Mapowanie literowego scenariusza na tryb QoS:
      A* -> 'none'
      B* -> 'htb'
      C* -> 'meter'
      default -> 'none'
    """
    s = s.lower()
    if s.startswith("a"):
        return "none"
    if s.startswith("b"):
        return "htb"
    if s.startswith("c"):
        return "meter"
    return "none"


def collect_switch_dpids(net) -> List[Tuple[str, int]]:
    """
    Zwraca listę krotek (nazwa_switcha, dpid_int) dla wszystkich switchy w sieci.
    DPID jest parsowany jako liczba z zapisu szesnastkowego.
    """
    out: List[Tuple[str, int]] = []
    for sw in net.switches:
        dpid_str = str(getattr(sw, "dpid", "") or "").strip()
        if not dpid_str:
            continue
        try:
            out.append((sw.name, int(dpid_str, 16)))
        except ValueError:
            # Pomijamy switche o nieprawidłowym DPID
            pass
    return sorted(out, key=lambda x: x[0])


def write_switch_dpids(dpids: List[Tuple[str, int]], out_path: str) -> None:
    """
    Zapisuje DPIDs do pliku tekstowego w prostym formacie:
      # switch_name  dpid_hex(0x...)  dpid_16hex
    """
    lines = []
    lines.append("# switch_name  dpid_hex(0x...)  dpid_16hex\n")
    for name, dpid_int in dpids:
        hex0x = f"0x{dpid_int:x}"
        hex16 = f"{dpid_int:016x}"
        lines.append(f"{name:8s}  {hex0x:>12s}  {hex16}\n")
    with open(out_path, "w") as f:
        f.writelines(lines)


# ---------- ovs/tc ----------

def clear_ovs_qos(dev: str) -> None:
    """
    Czyści konfigurację QoS na porcie OVS:
    - usuwa referencję QoS z portu,
    - usuwa wszystkie obiekty QoS oraz Queue.
    """
    sh(f"ovs-vsctl -- --if-exists clear port {dev} qos")
    sh("ovs-vsctl -- --all destroy QoS -- --all destroy Queue")


def destroy_tc_root(dev: str) -> None:
    """
    Kasuje root qdisc (tc) na danym urządzeniu.
    """
    sh(f"tc qdisc del dev {dev} root 2>/dev/null")


def apply_htb(
    dev: str,
    queues: Dict[int, Dict[str, int]],
    linkspeed_bits: Optional[int] = None,
) -> None:
    """
    Konfiguruje HTB w OVS na porcie `dev`:
    - tworzy obiekt QoS typu linux-htb,
    - dla każdej kolejki ustawia min/max-rate/burst/priority.

    queues:
      qid -> { "min": ..., "max": ..., "burst": ..., "priority": ... }
    """
    clear_ovs_qos(dev)

    parts: List[str] = [
        "ovs-vsctl -- ",
        f"set port {dev} qos=@qos -- ",
        "--id=@qos create QoS type=linux-htb ",
    ]

    # Opcjonalnie globalny max-rate na porcie
    if linkspeed_bits is not None:
        parts[2] = parts[2].rstrip() + f" other-config:max-rate={linkspeed_bits} "

    # Przypisanie kolejek do portu
    for qid in sorted(queues.keys()):
        parts.append(f"queues:{qid}=@q{qid} ")

    parts.append("-- ")

    # Definicje poszczególnych kolejek
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
    """
    Zwraca nazwę bridge'a OVS na podstawie nazwy interfejsu (część przed myślnikiem).
    Przykład: 'sp1-eth2' -> 'sp1'.
    """
    return dev.split("-")[0]


def disable_offloads(dev: str) -> None:
    """
    Wyłącza sprzętowe offloady (TSO/GSO/GRO) na interfejsie,
    żeby wyniki pomiarów były bardziej przewidywalne.
    """
    for feat in ("tso", "gso", "gro"):
        sh(f"ethtool -K {dev} {feat} off")


# ---------- mgmt sockets ----------

def find_ovs_rundir(user_hint: Optional[str] = None) -> Optional[str]:
    """
    Szuka katalogu z socketami OVS (*.mgmt).
    Kolejność:
      - user_hint (jeśli podany),
      - /var/run/openvswitch,
      - /run/openvswitch,
      - /usr/local/var/run/openvswitch.
    """
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


def wait_mgmt_target(
    bridge: str,
    timeout_s: float = 15.0,
    rundir_hint: Optional[str] = None,
) -> str:
    """
    Czeka aż pojawi się socket zarządzający (bridge.mgmt) dla podanego bridge'a.
    Zwraca uri w formie 'unix:/path/to/bridge.mgmt'.
    """
    deadline = time.time() + timeout_s
    last_listing = ""

    while time.time() < deadline:
        rd = find_ovs_rundir(rundir_hint)
        if rd:
            mgmt = os.path.join(rd, f"{bridge}.mgmt")
            if os.path.exists(mgmt):
                return f"unix:{mgmt}"

            ls = [f for f in os.listdir(rd) if f.endswith(".mgmt")]
            last_listing = " ".join(ls) if ls else "(brak *.mgmt)"
        time.sleep(0.2)

    raise RuntimeError(
        f"[OFCTL] Nie znaleziono socketa {bridge}.mgmt w typowych rundirach.\n"
        f"/var/run/openvswitch|/run/openvswitch|/usr/local/var/run/openvswitch:\n"
        f"{last_listing}"
    )


def dump_meters_and_stats(
    bridge: str,
    switch_dir: str,
    rundir_hint: Optional[str] = None,
) -> None:
    """
    Zrzuca konfigurację i statystyki meterów z OVS do pliku:
      switch_dir/{bridge}_meters.txt
    """
    target = wait_mgmt_target(bridge, timeout_s=15.0, rundir_hint=rundir_hint)
    cfg = sh(f"ovs-ofctl -O OpenFlow13 dump-meters {target}").stdout
    st = sh(f"ovs-ofctl -O OpenFlow13 meter-stats {target}").stdout
    with open(os.path.join(switch_dir, f"{bridge}_meters.txt"), "w") as f:
        f.write("=== dump-meters ===\n")
        f.write(cfg or "(empty)\n")
        f.write("\n=== meter-stats ===\n")
        f.write(st or "(empty)\n")


def assert_meters_present(
    bridge: str,
    expected_ids: List[int],
    rundir_hint: Optional[str] = None,
) -> None:
    """
    Sprawdza, czy dla danego bridge'a zainstalowane są metery o podanych ID.
    Przy braku – podnosi RuntimeError z dumpem konfiguracji.
    """
    target = wait_mgmt_target(bridge, timeout_s=15.0, rundir_hint=rundir_hint)
    out = sh(f"ovs-ofctl -O OpenFlow13 dump-meters {target}").stdout
    missing = [mid for mid in expected_ids if f"meter={mid}" not in out]
    if missing:
        raise RuntimeError(
            f"[METERS] Na {bridge} brakuje meterów {missing}.\nDump:\n{out}"
        )


# ---------- QoS scenarios ----------

def setup_qos_for_scenario(
    scenario: str,
    bottleneck_dev: str,
) -> str:
    """
    Konfiguruje QoS na porcie wąskiego gardła (bottleneck_dev)
    w zależności od scenariusza:
      'none'  – brak zmian,
      'htb'   – tworzy 3 kolejki HTB (EF/AF/BE),
      'meter' – kontroler ma zainstalować OF meters.
    """
    # Ustawiamy QOS_MODE w środowisku (m.in. dla Ryu)
    mode = scenario_to_qos_mode(scenario)
    os.environ["QOS_MODE"] = mode

    dev = bottleneck_dev
    clear_ovs_qos(dev)

    # Wyłączenie offloadów – nie jest krytyczne, więc łapiemy wyjątki
    try:
        disable_offloads(dev)
    except Exception:
        pass

    if mode == "none":
        info(f"[QoS] A/Baseline: brak zmian QoS na {dev}\n")

    elif mode == "meter":
        destroy_tc_root(dev)
        info("[QoS] C/METERS: przygotowanie pod metry (kontroler zainstaluje OF meters)\n")

    elif mode == "htb":
        destroy_tc_root(dev)
        # Stałe limity dla kolejek EF/AF/BE (bit/s)
        queues = {
            2: {"min": 60_000_000, "max": 60_000_000, "priority": 0, "burst": 200_000},   # EF (najwyższy priorytet)
            1: {"min": 30_000_000, "max": 30_000_000, "priority": 1, "burst": 250_000},   # AF
            0: {"min": 10_000_000, "max": 10_000_000, "priority": 2, "burst": 250_000},   # BE
        }
        apply_htb(dev, queues=queues, linkspeed_bits=None)
        info(f"[QoS] B/HTB: 3 kolejki na {dev} (EF=2, AF=1, BE=0)\n")

    else:
        info(f"[QoS] Nieznany tryb: {mode} — pomijam\n")

    return mode


# ---------- identify sp1 uplink (optional) ----------

def find_sp1_uplink(net: Mininet) -> Optional[str]:
    """
    Próbuje automatycznie wykryć uplink switche'a 'sp1':
    - szuka interfejsu połączonego ze switchem (nazwa nie zaczyna się od 'h').
    """
    try:
        sp1 = net.get("sp1")
    except Exception:
        return None

    for intf in sp1.intfList():
        if not intf or not getattr(intf, "link", None):
            continue

        other = intf.link.intf1 if intf.link.intf2 is intf else intf.link.intf2
        other_node = getattr(other, "node", None)
        other_name = getattr(other_node, "name", "")

        # pomijamy hosty (h1, h2, ...)
        if other_name and not other_name.startswith("h"):
            return str(intf)

    return None


# ---------- traffic ----------

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
    """
    Uruchamia 3 serwery iperf3 na hoście h2 (UDP, różne porty) i zapisuje logi.
    Zwraca mapę port -> nazwa pliku logu (ścieżki są w server_dir).
    """
    ports = [5201, 5202, 5203]
    for p in ports:
        h2.cmd(f'nohup iperf3 -s -p {p} > {server_dir}/srv_{p}.log 2>&1 &')
    return {
        5201: "srv_ef.log",
        5202: "srv_af31.log",
        5203: "srv_be.log",
    }


def run_iperf_clients(
    h1,
    client_dir: str,
    duration: int,
    ef_mbit: int,
    af_mbit: int,
    be_mbit: int,
) -> None:
    """
    Uruchamia z h1 trzy strumienie iperf3-UDP do h2 (10.0.0.2) z różnymi DSCP:
      - EF: DSCP 46, port 5201,
      - AF31: DSCP 26, port 5202,
      - BE: DSCP 0, port 5203.
    Logi w formacie JSON zapisywane są w client_dir.
    """
    flows = [
        # {"name": "ef",   "port": 5201, "mbit": ef_mbit, "dscp": DSCP_EF},
        {"name": "af31", "port": 5202, "mbit": af_mbit, "dscp": DSCP_AF31},
        # {"name": "be",   "port": 5203, "mbit": be_mbit, "dscp": DSCP_BE},
    ]

    for f in flows:
        tos = f["dscp"] << 2  # DSCP wchodzi w bity 2–7 pola ToS
        out_json = os.path.join(client_dir, f'{f["name"]}.json')

        cmd = (
            f'iperf3 -c 10.0.0.2 -p {f["port"]} -u '
            f'-b {f["mbit"]}M -t {duration} '
            f'-J --get-server-output --tos {tos} '
            f'--logfile {out_json} &'
        )
        h1.cmd(cmd)


def run_ping(h1, client_dir: str, duration: int) -> None:
    """
    Uruchamia pinga z h1 do h2 (10.0.0.2) na czas trwania eksperymentu.
    Wynik zapisany do client_dir/ping.txt.
    """
    count = max(1, int(duration * 10))
    h1.cmd(
        f'ping 10.0.0.2 -D -i 0.1 -c {count} '
        f'> {os.path.join(client_dir, "ping.txt")} 2>&1 &'
    )


# ---------- diag ----------

def dump_switch_state(
    switch_dir: str,
    rundir_hint: Optional[str],
    bridges: List[str],
    dump_ports_csv: str,
) -> None:
    """
    Zbiera stan switchy i kolejek:
      - dump-flows + show dla każdego bridge'a,
      - dump meterów,
      - tc qdisc/class + ovs-appctl qos/show dla wskazanych portów.
    """
    # Flows + metery
    for sw in bridges:
        target = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        sh(
            f'ovs-ofctl -O OpenFlow13 dump-flows {target} '
            f'> {os.path.join(switch_dir, f"{sw}_flows.txt")}'
        )
        sh(
            f'ovs-ofctl show {target} '
            f'>> {os.path.join(switch_dir, f"{sw}_flows.txt")}'
        )
        dump_meters_and_stats(sw, switch_dir, rundir_hint=rundir_hint)

    # Statystyki tc/OVS QoS dla wybranych portów
    ports = [p.strip() for p in dump_ports_csv.split(",") if p.strip()]
    for dev in ports:
        sh(
            f'tc -s qdisc show dev {dev} '
            f'> {os.path.join(switch_dir, f"{dev}_tc.txt")}'
        )
        sh(
            f'tc -s class show dev {dev} '
            f'> {os.path.join(switch_dir, f"{dev}_tc_class.txt")}'
        )
        sh(
            f'ovs-appctl qos/show {dev} '
            f'> {os.path.join(switch_dir, f"{dev}_qos.txt")}'
        )


def print_dump_flows(bridges: List[str], rundir_hint: Optional[str]) -> None:
    """
    Wyświetla na stdout dump-flows dla wszystkich bridge'y (na potrzeby diagnostyki).
    """
    for sw in bridges:
        info(f"\n--- dump-flows {sw} ({sw}.mgmt) ---\n")
        target = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        r = sh(f'ovs-ofctl -O OpenFlow13 dump-flows {target}')
        info(r.stdout if r.stdout else "(brak)\n")


def ping_all_n(net: Mininet, count: int = 1) -> float:
    """
    Wykonuje `net.pingAll()` `count` razy i zwraca średni procent strat.
    """
    total_loss = 0.0
    for _ in range(count):
        loss = net.pingAll()
        total_loss += loss
    return total_loss / max(1, count)


# ---------- main ----------

def main() -> None:
    """
    Główny runner eksperymentów QoS (EF/AF/BE) z Mininet + Ryu/RemoteController.
    """
    parser = argparse.ArgumentParser(
        description="SDN QoS test runner (EF/AF/BE)."
    )

    parser.add_argument("--topo-file", required=True)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument(
        "--scenario",
        required=True,
        help="A|B|C  (A=none, B=htb, C=meters)",
    )
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--dump-ports", default=BOTTLENECK_DEV_DEFAULT)
    parser.add_argument("--pcap-ifs", default="")
    parser.add_argument(
        "--bottleneck-dev",
        default=BOTTLENECK_DEV_DEFAULT,
        help="Port do QoS; specjalnie: 'auto-sp1' wykryje uplink sp1",
    )
    parser.add_argument("--verify-htb", action="store_true")

    parser.add_argument("--ef-mbit", type=int, default=IPERF_EF_MBIT)
    parser.add_argument("--af-mbit", type=int, default=IPERF_AF_MBIT)
    parser.add_argument("--be-mbit", type=int, default=IPERF_BE_MBIT)

    parser.add_argument(
        "--launch-ryu",
        default="",
        help="Ścieżka do aplikacji Ryu (opcjonalnie).",
    )
    parser.add_argument(
        "--ryu-extra",
        default="",
        help="Dodatkowe argumenty do ryu-manager (opcjonalnie).",
    )
    parser.add_argument(
        "--meter-dpids",
        default="0xd",
        help="DPID-y (np. '13') dla QOS_METER_DPIDS przy auto-launch Ryu.",
    )
    parser.add_argument(
        "--ovs-rundir",
        default="",
        help="Wymuszenie ścieżki z *.mgmt, jeśli różna niż standardowa.",
    )

    args = parser.parse_args()

    # Jeżeli użytkownik nie zmienił dump_ports, a zmienił bottleneck_dev,
    # to sensowniej jest dumpować to samo urządzenie co wąskie gardło.
    if args.dump_ports == BOTTLENECK_DEV_DEFAULT and args.bottleneck_dev != BOTTLENECK_DEV_DEFAULT:
        args.dump_ports = args.bottleneck_dev

    setLogLevel("info")

    # Wczytanie topologii z pliku
    topo = load_topo_from_file(args.topo_file)

    # Opcjonalne uruchomienie kontrolera Ryu w tle
    ryu_proc: Optional[subprocess.Popen] = None
    if args.launch_ryu:
        env = os.environ.copy()
        qos_mode = scenario_to_qos_mode(args.scenario)
        env["QOS_MODE"] = qos_mode
        env["QOS_EF_MBIT"] = str(args.ef_mbit)
        env["QOS_AF_MBIT"] = str(args.af_mbit)
        env["QOS_BE_MBIT"] = str(args.be_mbit)
        env.setdefault("QOS_EF_BURST_MB", "1")
        env.setdefault("QOS_AF_BURST_MB", "1")
        env.setdefault("QOS_BE_BURST_MB", "2")
        env["QOS_METER_DPIDS"] = args.meter_dpids if qos_mode == "meter" else ""

        cmd = [
            "ryu-manager",
            "--verbose",
            "--ofp-tcp-listen-port",
            str(args.controller_port),
            args.launch_ryu,
        ]
        if args.ryu_extra.strip():
            cmd.extend(args.ryu_extra.strip().split())

        info(
            f"* Launch Ryu: {' '.join(cmd)} "
            f"(QOS_MODE={env['QOS_MODE']}, "
            f"QOS_METER_DPIDS={env.get('QOS_METER_DPIDS','')})\n"
        )
        ryu_proc = popen(cmd, env=env)
        time.sleep(1.0)

    # Konfiguracja Mininet:
    # - link: TCLink z use_tbf=True,
    # - switche: OVSSwitch (OpenFlow13),
    # - controller: zewnętrzny (RemoteController).
    net = Mininet(
        topo=topo,
        controller=None,
        link=partial(TCLink, use_tbf=True),
        switch=partial(OVSSwitch, protocols="OpenFlow13"),
    )
    c0 = net.addController(
        name="c0",
        controller=RemoteController,
        ip=args.controller_ip,
        port=args.controller_port,
    )

    info("* Creating network\n")
    net.start()

    # Wypisanie mapy switch -> DPID
    dpid_map = collect_switch_dpids(net)
    info("\n=== Switch DPIDs (use in QOS_CLASSIFY_DPIDS) ===\n")
    for name, dpid_int in dpid_map:
        info(f"  {name:8s} -> 0x{dpid_int:x} (raw: {dpid_int:016x})\n")
    info("=== end ===\n\n")

    rundir_hint = args.ovs_rundir or None

    bridges: List[str] = [s.name for s in net.switches]
    info(f"* Bridges: {', '.join(bridges)}\n")

    # Sprawdzenie dostępności *.mgmt dla każdego bridge'a
    for sw in bridges:
        try:
            _ = wait_mgmt_target(sw, timeout_s=15.0, rundir_hint=rundir_hint)
        except Exception as e:
            info(f"[WARN] {e}\n")

    # Wybór interfejsu wąskiego gardła
    selected_dev = args.bottleneck_dev
    if args.bottleneck_dev.strip().lower() == "auto-sp1":
        auto_dev = find_sp1_uplink(net)
        if auto_dev:
            info(f"[QoS] Auto wybrano uplink sp1: {auto_dev}\n")
            selected_dev = auto_dev
        else:
            info(
                "[QoS][WARN] Nie znaleziono uplinku sp1, "
                "używam --bottleneck-dev bez zmian.\n"
            )

    info("* Starting controller\n")
    c0.start()

    # Szybki sanity-check: pingAll kilka razy
    info("\n=== Szybki pingAll (sanity) ===\n")
    loss = ping_all_n(net, count=3)
    info(f"PingAll loss ~ {loss}%\n")

    # Podgląd aktualnych flows
    print_dump_flows(bridges, rundir_hint)

    # Przygotowanie katalogów na logi
    run_dir, client_dir, server_dir, switch_dir, pcap_dir = make_dirs(
        args.log_dir, args.scenario
    )
    info(f"\n=== Katalog biegu: {run_dir} ===\n")

    # Konfiguracja QoS na wybranym porcie
    mode = setup_qos_for_scenario(args.scenario, selected_dev)

    # Dla scenariusza C – weryfikujemy, czy kontroler zainstalował metery
    if mode == "meter":
        info("[VERIFY] Oczekiwanie na instalację meterów przez kontroler...\n")
        time.sleep(1.0)
        meter_dpids = [
            p.strip()
            for p in (os.environ.get("QOS_METER_DPIDS") or args.meter_dpids).split(",")
            if p.strip()
        ]
        bridges_for_meter = [f"s{int(d)}" for d in meter_dpids if d.isdigit()] if meter_dpids else bridges

        for br in bridges_for_meter:
            try:
                assert_meters_present(br, [1, 2, 3], rundir_hint=rundir_hint)
                info(f"[VERIFY] {br}: metery 1,2,3 obecne.\n")
            except Exception as e:
                info(f"[WARN] {br}: {e}\n")

    # Opcjonalne zrzucenie konfiguracji HTB dla wybranego portu
    if args.verify_htb and mode == "htb":
        info(f"[VERIFY] Sprawdzam HTB na {selected_dev}\n")
        sh(
            f'tc -s qdisc show dev {selected_dev} '
            f'> {os.path.join(switch_dir, "htb_qdisc.txt")}'
        )
        sh(
            f'tc -s class show dev {selected_dev} '
            f'> {os.path.join(switch_dir, "htb_class.txt")}'
        )
        sh(
            f'ovs-appctl qos/show {selected_dev} '
            f'> {os.path.join(switch_dir, "htb_qos.txt")}'
        )

    # Opcjonalne nagrywanie ruchu tcpdumpem
    pcap_pids: List[int] = []
    if getattr(args, "pcap_ifs", "").strip():
        pcap_pids = start_pcap(net, args.pcap_ifs, pcap_dir, duration_hint=args.duration)
    info("\n=== Start klientów iperf3 ===\n")

    # Hosty końcowe
    h1 = net.get("h1")
    h2 = net.get("h2")

    # Serwery iperf3 na h2
    _ = start_iperf_servers(h2, server_dir)
    time.sleep(1.0)

    info(f"  -> EF (DSCP 46, {args.ef_mbit}M UDP, :5201)\n")
    info(f"  -> AF31 (DSCP 26, {args.af_mbit}M UDP, :5202)\n")
    info(f"  -> BE (DSCP 0, {args.be_mbit}M UDP, :5203)\n")

    # Klienci iperf3 + ping
    run_iperf_clients(h1, client_dir, args.duration, args.ef_mbit, args.af_mbit, args.be_mbit)
    run_ping(h1, client_dir, args.duration)

    # Czekamy aż testy się zakończą
    time.sleep(args.duration + 2)

    # Zbieramy stan switchy i kolejek
    dump_switch_state(switch_dir, rundir_hint, bridges, args.dump_ports)
    print_dump_flows(bridges, rundir_hint)

    # Metadane biegu
    with open(os.path.join(run_dir, "meta.txt"), "w") as f:
        f.write(f"scenario={args.scenario}\n")
        f.write(f"duration_s={args.duration}\n")
        f.write(f"controller={args.controller_ip}:{args.controller_port}\n")
        f.write("h1_ip=10.0.0.1\nh2_ip=10.0.0.2\n")
        f.write(f"bottleneck_dev={selected_dev}\n")
        f.write(f"qos_mode={scenario_to_qos_mode(args.scenario)}\n")
        f.write(f"dump_ports={args.dump_ports}\n")
        f.write(f"pcap_ifs={getattr(args, 'pcap_ifs', '')}\n")

    # Zatrzymanie tcpdumpów
    if pcap_pids:
        stop_pcap(pcap_pids)

    # Sprzątanie iperf3
    info("\n=== Sprzątanie iperf3 ===\n")
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    # Sprzątanie konfiguracji QoS/TC
    try:
        clear_ovs_qos(selected_dev)
        destroy_tc_root(selected_dev)
    except Exception:
        pass

    # Zatrzymanie Mininet
    net.stop()

    # Zatrzymanie Ryu (jeśli był odpalony lokalnie)
    if ryu_proc:
        try:
            ryu_proc.send_signal(signal.SIGINT)
            ryu_proc.wait(timeout=3)
        except Exception:
            ryu_proc.kill()

    info(f"\n=== KONIEC. Logi w: {run_dir} ===\n")


if __name__ == "__main__":
    main()
