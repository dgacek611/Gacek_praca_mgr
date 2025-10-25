"""
run_traffic.py — uruchamia testy EF/AF/BE, zbiera logi do współdzielonego folderu.

Struktura logów:
  /media/sf_Gacek_praca_mgr/logs/<SCENARIO>_YYYYmmdd_HHMMSS/
    clients/   -> ef.json, af31.json, be.json, ping.txt
    servers/   -> srv_ef.log, srv_af31.log, srv_be.log
    switch/    -> s1_flows.txt, s2_flows.txt, s3_flows.txt, <port>_tc.txt...
    pcap/      -> *.pcap (opcjonalnie)
    meta.txt   -> parametry biegu

WYMAGANIA:
- Mininet + OVS + iperf3
- Topologia w pliku podanym przez --topo-file z nazwą topo 'mytopo' (jak w project_topo_3_switches.py)
"""

import argparse
import os
import time
from datetime import datetime
from importlib.machinery import SourceFileLoader

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.clean import cleanup

# Porty iperf3
EF_PORT   = 5201
AF31_PORT = 5202
BE_PORT   = 5203

# DSCP: EF=0xB8 (46), AF31=0x68 (26), BE=0x00
EF_DSCP_HEX   = "0xB8"
AF31_DSCP_HEX = "0x68"
BE_DSCP_HEX   = "0x00"


def load_topo(topo_file_path):
    """Dynamicznie ładuje plik topologii i zwraca instancję topos['mytopo']()."""
    mod = SourceFileLoader("user_topo", topo_file_path).load_module()
    if not hasattr(mod, "topos") or "mytopo" not in mod.topos:
        raise RuntimeError("W pliku topologii nie znaleziono topos['mytopo'].")
    topo_callable = mod.topos["mytopo"]
    topo = topo_callable()
    return topo


def ping_all_n(net, count=1):
    """Prosty pingAll N-razy, zwraca średnią utratę w %."""
    total_loss = 0.0
    for _ in range(count):
        loss = net.pingAll()
        total_loss += loss
    return total_loss / max(1, count)


def make_dirs(base, scenario):
    """Tworzy strukturę katalogów dla biegu i zwraca ścieżki."""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir    = os.path.join(base, f"{scenario}_{ts}")
    client_dir = os.path.join(run_dir, "clients")
    server_dir = os.path.join(run_dir, "servers")
    switch_dir = os.path.join(run_dir, "switch")
    pcap_dir   = os.path.join(run_dir, "pcap")
    for d in (run_dir, client_dir, server_dir, switch_dir, pcap_dir):
        os.makedirs(d, exist_ok=True)
    return run_dir, client_dir, server_dir, switch_dir, pcap_dir


def start_servers(h2, server_dir):
    """Startuje 3 serwery iperf3 na h2 i loguje do server_dir."""
    # ubij stare serwery
    h2.cmd('pkill -f "iperf3 -s" || true')
    # odpal w tle (-D = daemon, --logfile)
    h2.cmd(f'iperf3 -s -p {EF_PORT}   -D --logfile {server_dir}/srv_ef.log')
    h2.cmd(f'iperf3 -s -p {AF31_PORT} -D --logfile {server_dir}/srv_af31.log')
    h2.cmd(f'iperf3 -s -p {BE_PORT}   -D --logfile {server_dir}/srv_be.log')
    time.sleep(0.4)


def start_clients(h1, h2ip, D, client_dir):
    """Startuje 3 klientów iperf3 z DSCP i JSON-em do client_dir + ping w tle."""
    # Ping RTT co 100 ms
    h1.cmd(f'ping -D -i 0.1 -w {D} {h2ip} > {client_dir}/ping.txt 2>&1 &')

    flows = [
        ("EF (DSCP 46, 5M UDP, :5201)",
         f'iperf3 -c {h2ip} -u -b 5M  -t {D} -S {EF_DSCP_HEX}   -p {EF_PORT}   -J --logfile {client_dir}/ef.json --get-server-output &'),
        ("AF31 (DSCP 26, 20M UDP, :5202)",
         f'iperf3 -c {h2ip} -u -b 20M -t {D} -S {AF31_DSCP_HEX} -p {AF31_PORT} -J --logfile {client_dir}/af31.json --get-server-output &'),
        ("BE (DSCP 0, 50M UDP, :5203)",
         f'iperf3 -c {h2ip} -u -b 50M -t {D} -S {BE_DSCP_HEX}   -p {BE_PORT}   -J --logfile {client_dir}/be.json --get-server-output &'),
    ]

    info('\n=== Start klientów iperf3 ===\n')
    for desc, cmd in flows:
        info(f'  -> {desc}\n')
        h1.cmd(cmd)


def dump_switch_state(switch_dir, dump_ports):
    """Zrzuca flowy OVS i (jeśli podano) statystyki kolejek TC."""
    os.system(f'ovs-ofctl -O OpenFlow13 dump-flows s1 > {switch_dir}/s1_flows.txt')
    os.system(f'ovs-ofctl -O OpenFlow13 dump-flows s2 > {switch_dir}/s2_flows.txt')
    os.system(f'ovs-ofctl -O OpenFlow13 dump-flows s3 > {switch_dir}/s3_flows.txt')

    if dump_ports:
        for p in dump_ports.split(','):
            p = p.strip()
            if p:
                os.system(f'tc -s qdisc show dev {p} > {switch_dir}/{p}_tc.txt')


def start_pcap(pcap_dir, pcap_ifs):
    """Opcjonalnie startuje tcpdump na zadanych interfejsach. Zwraca listę pidów."""
    pids = []
    if not pcap_ifs:
        return pids
    for idx, iface in enumerate([i.strip() for i in pcap_ifs.split(',') if i.strip()]):
        pcap_path = os.path.join(pcap_dir, f'cap_{idx+1}_{iface}.pcap')
        # -U: unbuffered, -s 120: snaplen
        os.system(f'tcpdump -i {iface} -w {pcap_path} -s 120 -U & echo $! >> {pcap_dir}/tcpdump.pids')
        pids.append(iface)
    return pids


def stop_pcap(pcap_dir):
    """Zatrzymuje tcpdump-y z pidów zapisanych w tcpdump.pids."""
    pidfile = os.path.join(pcap_dir, 'tcpdump.pids')
    if os.path.exists(pidfile):
        with open(pidfile) as f:
            pids = [ln.strip() for ln in f if ln.strip().isdigit()]
        for pid in pids:
            os.system(f'kill {pid} 2>/dev/null || true')


def main():
    parser = argparse.ArgumentParser(description="Ruch EF/AF/BE + logowanie do shared folderu.")
    parser.add_argument('--topo-file', required=True, help='Ścieżka do pliku z topologią Mininet (topos["mytopo"])')
    parser.add_argument('--controller-ip', default='127.0.0.1', help='IP kontrolera Ryu/SDN')
    parser.add_argument('--controller-port', type=int, default=6653, help='Port kontrolera')
    parser.add_argument('--duration', type=int, default=30, help='Czas testu w sekundach')
    parser.add_argument('--scenario', default='baseline', help='Etykieta scenariusza (A/B/C/D/E lub własna)')
    parser.add_argument('--log-dir', default='/media/sf_Gacek_praca_mgr/logs', help='Katalog bazowy na logi')
    parser.add_argument('--dump-ports', default='s2-eth2', help='Lista interfejsów OVS do tc -s (CSV), np. "s2-eth2,s3-eth2"')
    parser.add_argument('--pcap-ifs', default='', help='Lista interfejsów do przechwytywania (CSV), puste = wyłączone')
    parser.add_argument('--open-cli', action='store_true', help='Wejście do CLI Mininet po sanity check')
    args = parser.parse_args()

    setLogLevel('info')

    # 1) Import topologii i budowa sieci
    topo = load_topo(args.topo_file)
    net = Mininet(topo=topo,
                  controller=None,
                  switch=OVSSwitch,
                  link=TCLink,
                  autoSetMacs=True)

    ctrl = net.addController('c0', controller=RemoteController,
                             ip=args.controller_ip, port=args.controller_port)

    # 2) Start sieci
    net.start()
    time.sleep(1.0)

    # 3) (opcjonalne) jawne ustawienie kontrolera w OVS
    for sw in net.switches:
        sw.cmd(f'ovs-vsctl set-controller {sw.name} tcp:{args.controller_ip}:{args.controller_port}')
    time.sleep(1.0)

    # 4) Sanity: pingAll
    info('\n=== Szybki pingAll (sanity) ===\n')
    loss = ping_all_n(net, count=3)
    info(f'PingAll loss ~ {loss}%\n')

    # 5) Przygotowanie katalogów logów
    run_dir, client_dir, server_dir, switch_dir, pcap_dir = make_dirs(args.log_dir, args.scenario)
    info(f'\n=== Katalog biegu: {run_dir} ===\n')

    # 6) Hosty i katalogi po stronie hostów
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1.cmd(f'mkdir -p {client_dir}')
    h2.cmd(f'mkdir -p {server_dir}')

    # 7) Start serwerów i (opcjonalnie) PCAP
    start_servers(h2, server_dir)
    started_pcaps = start_pcap(pcap_dir, args.pcap_ifs)

    # 8) Start klientów (3 równoległe strumienie + ping)
    D = int(args.duration)
    start_clients(h1, h2.IP(), D, client_dir)

    # 9) Czas trwania testu
    time.sleep(D + 2)

    # 10) Zrzuty OVS/TC
    dump_switch_state(switch_dir, args.dump_ports)

    # 11) Zatrzymanie PCAP (jeśli było)
    stop_pcap(pcap_dir)

    # 12) Metryczka
    with open(os.path.join(run_dir, 'meta.txt'), 'w') as f:
        f.write(f'scenario={args.scenario}\n')
        f.write(f'duration_s={D}\n')
        f.write(f'controller={args.controller_ip}:{args.controller_port}\n')
        f.write(f'h1={h1.IP()} h2={h2.IP()}\n')
        f.write(f'dump_ports={args.dump_ports}\n')
        f.write(f'pcap_ifs={args.pcap_ifs}\n')

    # 13) Sprzątanie iperfów i Minineta
    info('\n=== Sprzątanie iperf3 ===\n')
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    net.stop()
    info(f'\n=== KONIEC. Logi w: {run_dir} ===\n')


if __name__ == '__main__':
    main()
