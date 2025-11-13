import argparse
import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Dict, List, Tuple, Optional

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

# ============================================================
#  Stałe DSCP / iPerf
# ============================================================

DSCP_EF = 46
DSCP_AF31 = 26
DSCP_BE = 0

IPERF_EF_MBIT = 40
IPERF_AF_MBIT = 40
IPERF_BE_MBIT = 40

# ============================================================
#  Pomocnicze funkcje shellowe
# ============================================================


def sh(
    cmd: str,
    check: bool = False,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess:
    """
    Proste wywołanie polecenia w shellu, z przechwyceniem stdout/stderr.

    :param cmd: Komenda powłoki.
    :param check: Jeśli True – rzuca wyjątek przy kodzie != 0.
    :param env: Nadpisane zmienne środowiskowe (opcjonalnie).
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
    env: Optional[Dict[str, str]] = None,
) -> subprocess.Popen:
    """
    Uruchom proces w trybie asynchronicznym (Popen).

    :param cmd: Komenda jako lista argumentów.
    :param env: Nadpisane zmienne środowiskowe (opcjonalnie).
    """
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )


# ============================================================
#  Wczytywanie topologii z pliku
# ============================================================


def load_topo_from_file(path: str):
    """
    Wczytuje topologię Mininet z pliku .py.

    Obsługiwane warianty:
    - dict `topos` z kluczami:
        - "polska"
        - "mytopo"
        - lub jeden jedyny element
    - klasy:
        - PolskaTopo
        - MyTopo
    """
    spec = importlib.util.spec_from_file_location("user_topo", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[assignment]
    assert spec and spec.loader, "Bad topo module."
    spec.loader.exec_module(mod)  # type: ignore[arg-type]

    topo = None

    if hasattr(mod, "topos") and isinstance(mod.topos, dict) and mod.topos:
        if "polska" in mod.topos:
            topo = mod.topos["polska"]()
        elif "mytopo" in mod.topos:
            topo = mod.topos["mytopo"]()
        elif len(mod.topos) == 1:
            topo = next(iter(mod.topos.values()))()

    if topo is None and hasattr(mod, "PolskaTopo"):
        topo = mod.PolskaTopo()

    if topo is None and hasattr(mod, "MyTopo"):
        topo = mod.MyTopo()

    if topo is None:
        raise RuntimeError("Nie znaleziono topologii w pliku.")

    return topo


# ============================================================
#  Katalogi i logi
# ============================================================


def _timestamp_local() -> str:
    """
    Zwraca znacznik czasu w lokalnej strefie (UTC+1) w formacie YYYYmmdd_HHMMSS.
    """
    tz = timezone(timedelta(hours=1))
    return (
        datetime.now(timezone.utc)
        .astimezone(tz)
        .strftime("%Y%m%d_%H%M%S")
    )


def make_dirs(base: str, scenario: str) -> Tuple[str, str, str, str]:
    """
    Tworzy strukturę katalogów dla pojedynczego uruchomienia.

    :param base: Bazowy katalog logów.
    :param scenario: Nazwa scenariusza (A/B/...).
    :return: (run_dir, client_dir, server_dir, switch_dir)
    """
    run_dir = os.path.join(base, f"{scenario}_{_timestamp_local()}")
    client_dir = os.path.join(run_dir, "clients")
    server_dir = os.path.join(run_dir, "servers")
    switch_dir = os.path.join(run_dir, "switch")

    os.makedirs(client_dir, exist_ok=True)
    os.makedirs(server_dir, exist_ok=True)
    os.makedirs(switch_dir, exist_ok=True)

    return run_dir, client_dir, server_dir, switch_dir


# ============================================================
#  Uruchamianie iPerf / ping
# ============================================================


def start_iperf_servers(h2, server_dir: str) -> None:
    """
    Uruchamia trzy serwery iPerf3 (UDP) na porcie 5201/5202/5203 na hoście h2.

    Logi serwera trafiają do server_dir/srv_<port>.log.
    """
    for port in (5201, 5202, 5203):
        h2.cmd(
            f"nohup iperf3 -s -p {port} > {server_dir}/srv_{port}.log 2>&1 &"
        )


def run_iperf_clients(
    h1,
    client_dir: str,
    duration: int,
    ef_mbit: int,
    af_mbit: int,
    be_mbit: int,
) -> None:
    """
    Uruchamia trzy klienty iPerf3 UDP na hoście h1:
    - EF  -> port 5201, DSCP_EF
    - AF31 -> port 5202, DSCP_AF31
    - BE  -> port 5203, DSCP_BE

    Każdy zapisuje wynik w formacie JSON do client_dir/<nazwa>.json.
    """
    flows = [
        {"name": "ef", "port": 5201, "mbit": ef_mbit, "dscp": DSCP_EF},
        {"name": "af31", "port": 5202, "mbit": af_mbit, "dscp": DSCP_AF31},
        {"name": "be", "port": 5203, "mbit": be_mbit, "dscp": DSCP_BE},
    ]

    for f in flows:
        tos = f["dscp"] << 2
        out_json = os.path.join(client_dir, f'{f["name"]}.json')

        cmd = (
            f"iperf3 -c 10.0.0.2 -p {f['port']} -u "
            f"-b {f['mbit']}M -t {duration} -J --get-server-output --tos {tos} "
            f"--logfile {out_json} &"
        )
        h1.cmd(cmd)


def run_ping_class(
    h1,
    dscp: int,
    out_path: str,
    duration_s: int,
) -> None:
    """
    Uruchamia ping do h2 (10.0.0.2) z zadanym DSCP i zapisuje wynik do pliku.

    :param dscp: Wartość DSCP (bity 6..1 nagłówka IP).
    :param out_path: Ścieżka do pliku z logiem.
    :param duration_s: Czas trwania w sekundach.
    """
    tos = dscp << 2
    count = max(1, int(duration_s * 10))  # co 0.1 s
    h1.cmd(
        f"ping 10.0.0.2 -D -i 0.1 -c {count} -Q {tos} "
        f"> {out_path} 2>&1 &"
    )


# ============================================================
#  Kontrola awarii (failover)
# ============================================================


def failover_thread(
    net: Mininet,
    s1: str,
    s2: str,
    fail_at: float,
    up_after: float,
    events_path: str,
) -> None:
    """
    Wątek odpowiedzialny za:
    - wyłączenie linku s1<->s2 o zadanym czasie (fail_at),
    - ewentualne ponowne włączenie po up_after sekundach.

    Wszystkie zdarzenia zapisywane są do events_path.
    """
    t0 = time.time()

    def ts() -> str:
        """Zwraca czas względny od startu wątku, w sekundach."""
        return f"{time.time() - t0:.3f}s"

    with open(events_path, "w") as f:
        f.write("[0.000s] runner_start\n")

        time.sleep(max(0.0, fail_at))
        try:
            net.configLinkStatus(s1, s2, "down")
            f.write(f"[{ts()}] link_down {s1}<->{s2}\n")
        except Exception as exc:  # noqa: BLE001
            f.write(f"[{ts()}] link_down_error {s1}<->{s2} {exc}\n")

        if up_after > 0:
            time.sleep(up_after)
            try:
                net.configLinkStatus(s1, s2, "up")
                f.write(f"[{ts()}] link_up {s1}<->{s2}\n")
            except Exception as exc:  # noqa: BLE001
                f.write(f"[{ts()}] link_up_error {s1}<->{s2} {exc}\n")


# ============================================================
#  Parsowanie wyników iPerf
# ============================================================


def parse_iperf_intervals(json_path: str) -> List[Tuple[float, float]]:
    """
    Wczytuje plik JSON z iPerf3 i zwraca listę (czas_konca_okna, Mbps).

    Jeśli plik nie istnieje lub niepoprawny – zwraca pustą listę.
    """
    if not os.path.exists(json_path):
        return []

    try:
        with open(json_path) as f:
            data = json.load(f)

        intervals: List[Tuple[float, float]] = []
        for iv in data.get("intervals", []):
            t = float(iv.get("sum", {}).get("end", 0.0))
            bps = float(iv.get("sum", {}).get("bits_per_second", 0.0))
            intervals.append((t, bps / 1e6))  # na Mbps

        return intervals
    except Exception:  # noqa: BLE001
        return []


# ============================================================
#  Weryfikacja iPerf (EF/AF/BE)
# ============================================================


def evaluate_failover(
    ef_iv: List[Tuple[float, float]],
    af_iv: List[Tuple[float, float]],
    be_iv: List[Tuple[float, float]],
    fail_at: float,
    window: float,
    ef_target_mbit: float,
    ef_keep_ratio: float,
    stall_threshold_mbps: float,
) -> Dict[str, str]:
    """
    Ocena zachowania klas ruchu w oknie awarii (iPerf).

    EF:
        min_throughput w oknie >= ef_target_mbit * ef_keep_ratio -> PASS
    AF/BE:
        min_throughput w oknie <= stall_threshold_mbps          -> PASS
    """

    lo = max(0.0, fail_at - window)
    hi = fail_at + window

    def min_in_window(intervals: List[Tuple[float, float]]) -> float:
        """Minimalny throughput w zadanym oknie czasowym."""
        values = [mb for (t, mb) in intervals if lo <= t <= hi]
        return min(values) if values else float("inf")

    ef_min = min_in_window(ef_iv)
    af_min = min_in_window(af_iv)
    be_min = min_in_window(be_iv)

    verdict: Dict[str, str] = {}

    # EF – oczekujemy utrzymania przepustowości
    ef_threshold = ef_target_mbit * ef_keep_ratio
    if ef_min >= ef_threshold:
        verdict["EF"] = "PASS (min=%.2f Mbps >= %.2f)" % (ef_min, ef_threshold)
    else:
        verdict["EF"] = "FAIL (min=%.2f Mbps < %.2f)" % (ef_min, ef_threshold)

    # AF – oczekujemy przestoju (przepustowość ~0)
    if af_min <= stall_threshold_mbps:
        verdict["AF"] = "PASS (min=%.2f Mbps <= %.2f)" % (
            af_min,
            stall_threshold_mbps,
        )
    else:
        verdict["AF"] = "FAIL (min=%.2f Mbps > %.2f)" % (
            af_min,
            stall_threshold_mbps,
        )

    # BE – podobnie jak AF
    if be_min <= stall_threshold_mbps:
        verdict["BE"] = "PASS (min=%.2f Mbps <= %.2f)" % (
            be_min,
            stall_threshold_mbps,
        )
    else:
        verdict["BE"] = "FAIL (min=%.2f Mbps > %.2f)" % (
            be_min,
            stall_threshold_mbps,
        )

    return verdict


# ============================================================
#  Precheck pingAll
# ============================================================


def precheck_connectivity(
    net: Mininet,
    attempts: int,
    sleep_sec: float,
    precheck_path: str,
) -> bool:
    """
    Wykonuje kilka prób pingAll() i zapisuje wynik do pliku.

    :return: True jeśli we wszystkich próbach straty wyniosły 0%.
    """
    ok_all = True

    with open(precheck_path, "w") as f:
        for i in range(1, attempts + 1):
            loss = net.pingAll()
            line = f"attempt={i} loss={loss:.2f}%\n"
            f.write(line)
            info(f"[PRECHECK] {line}")

            if loss > 0.0:
                ok_all = False

            if i < attempts:
                time.sleep(max(0.0, sleep_sec))

    return ok_all


# ============================================================
#  FF verify: OVS group stats (sampling + analiza)
# ============================================================


def _mgmt_target(sw_name: str) -> str:
    """
    Zwraca adres mgmt dla ovs-ofctl:
    - jeśli istnieje gniazdo /var/run/openvswitch/<sw>.mgmt -> unix:<ścieżka>
    - inaczej po prostu nazwa przełącznika.
    """
    mgmt = f"/var/run/openvswitch/{sw_name}.mgmt"
    return f"unix:{mgmt}" if os.path.exists(mgmt) else sw_name


def dump_group_stats_text(sw: str) -> str:
    """
    Zwraca surowy tekst z 'ovs-ofctl dump-group-stats' dla przełącznika.
    """
    return sh(
        f"ovs-ofctl -O OpenFlow13 dump-group-stats {_mgmt_target(sw)}"
    ).stdout


# RegEx do parsowania statystyk grup/bucketów
__BUCKET_RE = re.compile(
    r"bucket=(\d+):.*?packet_count=(\d+),\s*byte_count=(\d+)",
    re.IGNORECASE,
)
_GROUP_RE = re.compile(
    r"group_id=(\d+),\s*ref_count=\d+",
    re.IGNORECASE,
)


def parse_group_stats(sw: str, text: str) -> List[Tuple[str, int, int, int]]:
    """
    Parsuje output 'dump-group-stats'.

    Zwraca listę krotek:
        (nazwa_switcha, group_id, bucket_id, packet_count)
    """
    out: List[Tuple[str, int, int, int]] = []
    gid: Optional[int] = None

    for line in text.splitlines():
        m = _GROUP_RE.search(line)
        if m:
            gid = int(m.group(1))
            continue

        b = __BUCKET_RE.search(line)
        if gid is not None and b:
            out.append((sw, gid, int(b.group(1)), int(b.group(2))))

    return out


def ff_sampler_thread(
    net: Mininet,
    switches: List[str],
    start_at: float,
    stop_at: float,
    interval: float,
    out_csv: str,
    t0: float,
) -> None:
    """
    Wątek próbkujący OVS group stats.

    Co `interval` sekund w oknie [start_at, stop_at] wykonuje dump-group-stats
    dla wszystkich przełączników i zapisuje CSV:
        t,sw,group_id,bucket,packets
    """
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)

    with open(out_csv, "w") as f:
        f.write("t,sw,group_id,bucket,packets\n")

        now = time.time() - t0
        # poczekaj do okna startowego
        if now < start_at:
            time.sleep(start_at - now)

        while True:
            t_rel = time.time() - t0
            if t_rel > stop_at + 1e-6:
                break

            for sw in switches:
                txt = dump_group_stats_text(sw)
                for sw_name, gid, bucket, pkts in parse_group_stats(sw, txt):
                    f.write(
                        f"{t_rel:.3f},{sw_name},{gid},{bucket},{pkts}\n"
                    )

            time.sleep(max(0.0, interval))


def analyze_ff_samples(
    csv_path: str,
    fail_at: float,
    pre: float,
    post: float,
) -> Tuple[bool, List[str]]:
    """
    Analiza próbek FF (Fast Failover) na podstawie CSV.

    Idea:
    - Dla każdej pary (sw, group_id):
        - kubełek #1 (primary) powinien rosnąć PRZED awarią i przestać po awarii.
        - kubełek #2 (backup) powinien zacząć rosnąć PO awarii.
    - Jeśli znajdziemy przynajmniej jeden taki przypadek -> FF_PASS.

    :return:
        (ff_pass, lista_opisów)
    """
    if not os.path.exists(csv_path):
        return False, ["FF_SAMPLES_MISSING"]

    from collections import defaultdict

    rows: List[Tuple[float, str, int, int, int]] = []

    # wczytanie CSV
    with open(csv_path) as f:
        next(f, None)  # pomiń nagłówek
        for line in f:
            t_s, sw, gid_s, b_s, pk_s = line.strip().split(",")
            rows.append(
                (float(t_s), sw, int(gid_s), int(b_s), int(pk_s))
            )

    # zbuduj serię czasową per (sw, gid, bucket)
    series: Dict[
        Tuple[str, int, int], List[Tuple[float, int]]
    ] = defaultdict(list)

    for t, sw, gid, bucket, pk in rows:
        series[(sw, gid, bucket)].append((t, pk))

    ff_match_list: List[str] = []

    def delta_in_window(
        pts: List[Tuple[float, int]],
        lo: float,
        hi: float,
    ) -> int:
        """
        Zwraca przyrost pakietów (max - min) w danym oknie czasowym.
        """
        values = [pk for (t, pk) in pts if lo <= t <= hi]
        if not values:
            return 0
        return max(values) - min(values)

    # analiza dla każdej grupy
    unique_keys = {(sw, gid) for (sw, gid, _) in series.keys()}

    for sw, gid in unique_keys:
        b1 = series.get((sw, gid, 1), [])
        b2 = series.get((sw, gid, 2), [])

        if not b1 or not b2:
            # wymagana obecność 2 kubełków
            continue

        lo_pre = max(0.0, fail_at - pre)
        hi_pre = fail_at - 1e-6
        lo_post = fail_at + 1e-6
        hi_post = fail_at + post

        d1_pre = delta_in_window(b1, lo_pre, hi_pre)
        d1_post = delta_in_window(b1, lo_post, hi_post)
        d2_pre = delta_in_window(b2, lo_pre, hi_pre)
        d2_post = delta_in_window(b2, lo_post, hi_post)

        # Proste heurystyki:
        # - przed awarią primary rośnie (d1_pre > 0)
        # - po awarii backup rośnie (d2_post > 0)
        # - primary po awarii praktycznie stoi (d1_post <= 1)
        if d1_pre > 0 and d2_post > 0 and d1_post <= 1:
            ff_match_list.append(
                f"{sw}:group={gid} "
                f"(Δpri_pre={d1_pre}, Δpri_post={d1_post}, "
                f"Δbkp_pre={d2_pre}, Δbkp_post={d2_post})"
            )

    return (len(ff_match_list) > 0), ff_match_list


# ============================================================
#  Główna funkcja
# ============================================================


def main() -> None:
    """
    Punkt wejścia:
    - wczytuje topologię,
    - opcjonalnie uruchamia kontroler Ryu,
    - odpala Mininet,
    - robi precheck,
    - uruchamia iPerf + scenariusz awarii,
    - zbiera logi i generuje werdykt.
    """
    parser = argparse.ArgumentParser(
        description=(
            "FF test: iPerf EF/AF/BE + link down + PASS/FAIL + FF verification."
        )
    )

    # Parametry ogólne
    parser.add_argument("--topo-file", required=True)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--scenario", default="A")
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--fail-link", default="s1,s11")
    parser.add_argument("--fail-at", type=float, default=10.0)
    parser.add_argument("--fail-up-after", type=float, default=0.0)

    # iPerf parametry klas
    parser.add_argument(
        "--ef-mbit",
        type=int,
        default=IPERF_EF_MBIT,
    )
    parser.add_argument(
        "--af-mbit",
        type=int,
        default=IPERF_AF_MBIT,
    )
    parser.add_argument(
        "--be-mbit",
        type=int,
        default=IPERF_BE_MBIT,
    )

    # Kontroler Ryu
    parser.add_argument(
        "--launch-ryu",
        default="",
        help="np. /app/ryu_class_routing.py",
    )
    parser.add_argument("--ryu-extra", default="")

    # Okno analizy awarii
    parser.add_argument("--window", type=float, default=2.0)
    parser.add_argument("--ef-keep-ratio", type=float, default=0.7)
    parser.add_argument(
        "--stall-threshold-mbps",
        type=float,
        default=0.1,
    )

    # Precheck pingAll
    parser.add_argument("--precheck-attempts", type=int, default=3)
    parser.add_argument("--precheck-sleep", type=float, default=1.0)

    # FF verification sampling
    parser.add_argument(
        "--ff-verify",
        action="store_true",
        help="Włącz próbnik dump-group-stats wokół awarii",
    )
    parser.add_argument(
        "--ff-pre",
        type=float,
        default=1.0,
        help="okno PRE przed fail_at (s)",
    )
    parser.add_argument(
        "--ff-post",
        type=float,
        default=3.0,
        help="okno POST po fail_at (s)",
    )
    parser.add_argument(
        "--ff-interval",
        type=float,
        default=0.5,
        help="krok próbkowania (s)",
    )

    args = parser.parse_args()

    setLogLevel("info")

    # --- Topologia ---
    topo = load_topo_from_file(args.topo_file)

    # --- Opcjonalne uruchomienie Ryu ---
    ryu_proc: Optional[subprocess.Popen] = None
    if args.launch_ryu:
        env = os.environ.copy()
        env["CBR_DEBUG"] = "1"

        cmd = [
            "ryu-manager",
            "--verbose",
            "--ofp-tcp-listen-port",
            str(args.controller_port),
            args.launch_ryu,
        ]
        if args.ryu_extra.strip():
            cmd.extend(args.ryu_extra.strip().split())

        info(f"* Launch Ryu: {' '.join(cmd)}\n")
        ryu_proc = popen(cmd, env=env)
        time.sleep(1.0)

    # --- Mininet ---
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

    info("* Start sieci\n")
    net.start()
    c0.start()

    # --- Katalogi logów ---
    run_dir, client_dir, server_dir, switch_dir = make_dirs(
        args.log_dir,
        args.scenario,
    )
    info(f"\n=== RUN DIR: {run_dir} ===\n")

    # --- PRECHECK connectivity ---
    precheck_path = os.path.join(run_dir, "precheck.txt")
    info(f"* Precheck pingAll x{args.precheck_attempts}\n")

    if not precheck_connectivity(
        net,
        args.precheck_attempts,
        args.precheck_sleep,
        precheck_path,
    ):
        info(
            "\n[PRECHECK] FAIL: sieć nie osiągnęła 100% reachability.\n"
        )

    # --- Hosty ---
    h1 = net.get("h1")
    h2 = net.get("h2")

    # --- Start serwerów iPerf ---
    start_iperf_servers(h2, server_dir)
    time.sleep(1.0)

    info("\n=== Start iPerf3 (EF/AF/BE) ===\n")
    run_iperf_clients(
        h1,
        client_dir,
        args.duration,
        args.ef_mbit,
        args.af_mbit,
        args.be_mbit,
    )

    # --- FF sampler (opcjonalnie) ---
    sampler_thr: Optional[threading.Thread] = None
    ff_csv = os.path.join(run_dir, "ff_samples.csv")
    t0 = time.time()
    sw_names = [s.name for s in net.switches]

    if args.ff_verify:
        start_at = max(0.0, args.fail_at - args.ff_pre)
        stop_at = args.fail_at + args.ff_post

        info(
            f"[FF] sampling groups on {len(sw_names)} switches "
            f"in [{start_at:.2f}s,{stop_at:.2f}s] every "
            f"{args.ff_interval:.2f}s\n"
        )

        sampler_thr = threading.Thread(
            target=ff_sampler_thread,
            args=(
                net,
                sw_names,
                start_at,
                stop_at,
                args.ff_interval,
                ff_csv,
                t0,
            ),
            daemon=True,
        )
        sampler_thr.start()

    # --- Awaria linku (failover) ---
    evt_path = os.path.join(run_dir, "events.txt")
    sA, sB = [x.strip() for x in args.fail_link.split(",")]

    info(
        f"[FAIL] {sA}<{'>'.join(['', ''])}{sB} @ "
        f"{args.fail_at}s (up after {args.fail_up_after}s)\n"
    )
    fail_thr = threading.Thread(
        target=failover_thread,
        args=(
            net,
            sA,
            sB,
            args.fail_at,
            args.fail_up_after,
            evt_path,
        ),
        daemon=True,
    )
    fail_thr.start()

    # --- Czekamy na koniec testu ---
    time.sleep(args.duration + 2.0)
    fail_thr.join(timeout=1.0)

    if sampler_thr:
        sampler_thr.join(timeout=1.0)

    # --- Debug: zrzuty OVS ---
    for sw in sw_names:
        target = _mgmt_target(sw)
        out_path = os.path.join(switch_dir, f"{sw}_flows.txt")

        sh(
            f"ovs-ofctl -O OpenFlow13 dump-flows {target} > {out_path}"
        )
        sh(
            f"ovs-ofctl -O OpenFlow13 dump-groups {target} >> {out_path}"
        )
        sh(
            f"ovs-ofctl -O OpenFlow13 dump-group-stats {target} >> {out_path}"
        )
        sh(f"ovs-ofctl -O OpenFlow13 show {target} >> {out_path}")

    # --- Parsowanie wyników iPerf ---
    def _iv(name: str) -> List[Tuple[float, float]]:
        return parse_iperf_intervals(os.path.join(client_dir, name))

    ef_iv = _iv("ef.json")
    af_iv = _iv("af31.json")
    be_iv = _iv("be.json")

    verdict = evaluate_failover(
        ef_iv,
        af_iv,
        be_iv,
        args.fail_at,
        args.window,
        float(args.ef_mbit),
        args.ef_keep_ratio,
        args.stall_threshold_mbps,
    )

    # --- FF verification (analiza) ---
    ff_pass = False
    ff_details: List[str] = ["FF_VERIFY_DISABLED"]

    if args.ff_verify:
        ff_pass, ff_details = analyze_ff_samples(
            ff_csv,
            fail_at=args.fail_at,
            pre=args.ff_pre,
            post=args.ff_post,
        )

    # --- Zapis werdyktu ---
    verdict_path = os.path.join(run_dir, "verdict.txt")
    with open(verdict_path, "w") as f:
        f.write("# PASS/FAIL w oknie awarii (iPerf)\n")
        f.write(f"EF: {verdict['EF']}\n")
        f.write(f"AF: {verdict['AF']}\n")
        f.write(f"BE: {verdict['BE']}\n")

        f.write(
            "\nOkno analizy: "
            f"[{max(0.0, args.fail_at - args.window):.2f}s, "
            f"{args.fail_at + args.window:.2f}s]\n"
        )

        f.write("\n# FF verification (group stats)\n")
        f.write("FF: PASS\n" if ff_pass else "FF: FAIL\n")
        for line in ff_details:
            f.write(f"- {line}\n")

    # --- Podsumowanie na stdout ---
    info("\n=== VERDICT ===\n")
    info(
        f"EF: {verdict['EF']}\nAF: {verdict['AF']}\nBE: {verdict['BE']}\n"
    )

    if args.ff_verify:
        info(f"FF: {'PASS' if ff_pass else 'FAIL'}\n")
    else:
        info("FF: DISABLED\n")

    # --- Sprzątanie ---
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    net.stop()

    if ryu_proc:
        try:
            ryu_proc.send_signal(signal.SIGINT)
            ryu_proc.wait(timeout=3)
        except Exception:  # noqa: BLE001
            ryu_proc.kill()

    info(f"\n=== KONIEC. Logi: {run_dir} ===\n")


if __name__ == "__main__":
    main()
