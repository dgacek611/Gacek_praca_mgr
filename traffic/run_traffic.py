#!/usr/bin/env python3
# run_traffic.py

import argparse
import time
from importlib.machinery import SourceFileLoader
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.clean import cleanup

EF_PORT   = 5201
AF31_PORT = 5202
BE_PORT   = 5203

def load_topo_class(path, clsname="MyTopo"):
    mod = SourceFileLoader("user_topo", path).load_module()
    return getattr(mod, clsname)

def setup_ovs_protocols_and_stp(net, enable_stp=True):
    for sw in net.switches:
        # OF1.3 + (opcjonalnie) STP
        sw.cmd(f'ovs-vsctl set Bridge {sw.name} protocols=OpenFlow13')
        if enable_stp:
            sw.cmd(f'ovs-vsctl set Bridge {sw.name} stp_enable=true')

def verify_stp(net, wait_sec=35):
    info(f'\n=== Czekam {wait_sec}s na konwergencję STP ===\n')
    time.sleep(wait_sec)
    info('\n=== Weryfikacja STP (ovs-vsctl get / ovs-appctl stp/show) ===\n')
    for sw in net.switches:
        enabled = sw.cmd(f'ovs-vsctl get Bridge {sw.name} stp_enable').strip()
        info(f'Bridge {sw.name} stp_enable={enabled}\n')
    for sw in net.switches:
        stp_info = sw.cmd(f'ovs-appctl stp/show {sw.name}')
        info(f'\n--- STP status for {sw.name} ---\n{stp_info}\n')

def main():
    setLogLevel('info')
    ap = argparse.ArgumentParser()
    ap.add_argument('--topo-file', required=True, help='Ścieżka do pliku z klasą MyTopo')
    ap.add_argument('--controller-ip', default='127.0.0.1')
    ap.add_argument('--controller-port', type=int, default=6653)
    ap.add_argument('--duration', type=int, default=30, help='Czas testów w sekundach')
    ap.add_argument('--open-cli', action='store_true', help='Po testach zostaw CLI Minineta')
    args = ap.parse_args()

    # 1) Topologia
    TopoClass = load_topo_class(args.topo_file)

    # 2) Mininet + kontroler zdalny (Ryu)
    net = Mininet(
        topo=TopoClass(),
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=True,
        build=True
    )
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip=args.controller_ip,
        port=args.controller_port
    )

    net.start()

    # Wymuś kontroler na każdym bridge’u (gdyby OVS startował bez kontrolera)
    for sw in net.switches:
        sw.cmd(f'ovs-vsctl set-controller {sw.name} tcp:{args.controller_ip}:{args.controller_port}')

    # 3) OF1.3 + STP
    setup_ovs_protocols_and_stp(net, enable_stp=True)
    verify_stp(net, wait_sec=35)

    # 4) Szybki sanity-check
    info('\n=== Szybki pingAll (sanity) ===\n')
    loss = net.pingAll()
    info(f'PingAll loss: {loss}%\n')

    h1, h2 = net.get('h1', 'h2')

    info('\n=== Adresy hostów ===\n')
    info(f"h1: {h1.IP()}\n")
    info(f"h2: {h2.IP()}\n")

    info('\n=== Ping h1 -> h2 (1 pakiet) ===\n')
    info(h1.cmd(f'ping -c 1 {h2.IP()}'))

    # 5) iperf3: 3 SERWERY na h2 (różne porty)
    info('\n=== Start iperf3 servers on h2 (5201/5202/5203) ===\n')
    h2.cmd('pkill -f "iperf3 -s"')
    h2.cmd(f'iperf3 -s -p {EF_PORT}   -D')
    h2.cmd(f'iperf3 -s -p {AF31_PORT} -D')
    h2.cmd(f'iperf3 -s -p {BE_PORT}   -D')
    info(h2.cmd('ss -ulpn | grep iperf3 || true'))

    # 6) 3 KLIENCI jednocześnie na h1 (różne DSCP/bitraty/porty)
    D = args.duration
    flows = [
        ("EF (DSCP 46, 5M UDP, :5201)",
         f'iperf3 -c {h2.IP()} -u -b 5M  -t {D} -S 0xB8 -p {EF_PORT}   --get-server-output > /tmp/ef.log 2>&1 &'),
        ("AF31 (DSCP 26, 20M UDP, :5202)",
         f'iperf3 -c {h2.IP()} -u -b 20M -t {D} -S 0x68 -p {AF31_PORT} --get-server-output > /tmp/af31.log 2>&1 &'),
        ("BE (DSCP 0, 50M UDP, :5203)",
         f'iperf3 -c {h2.IP()} -u -b 50M -t {D} -S 0x00 -p {BE_PORT}   --get-server-output > /tmp/be.log 2>&1 &'),
    ]

    info('\n=== Start klientów na h1 (równolegle) ===\n')
    for desc, cmd in flows:
        info(f'[*] {desc}\n')
        h1.cmd(cmd)

    info(f'\n=== Testy w toku (~{D}s) ===\n')
    time.sleep(D + 2)

    # 7) Podsumowanie logów klientów
    info('\n=== Wyniki (tail z logów klientów na h1) ===\n')
    for name in ['ef', 'af31', 'be']:
        info(f'\n--- /tmp/{name}.log (ostatnie linie) ---\n')
        info(h1.cmd(f'tail -n 12 /tmp/{name}.log || true'))

    if args.open_cli:
        info('\n=== Wejście do CLI Mininet (Ctrl-D aby wyjść) ===\n')
        CLI(net)

    # 8) Sprzątanie iperfów i Minineta
    info('\n=== Sprzątanie iperf3 ===\n')
    h1.cmd('pkill -f "iperf3 -c" || true')
    h2.cmd('pkill -f "iperf3 -s" || true')

    net.stop()

if __name__ == '__main__':
    main()
