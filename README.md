# Analiza możliwości wykorzystania koncepcji SDN do dynamicznej kontroli QoS w sieciach opartych na MPLS i DiffServ

T1:
sudo -E python3 /media/sf_Gacek_praca_mgr/traffic/run_traffic.py \
  --topo-file /media/sf_Gacek_praca_mgr/mininet_topo/project_topo_3_switches.py \
  --controller-ip 127.0.0.1 --controller-port 6653 \
  --duration 60 \
  --scenario a \
  --log-dir /media/sf_Gacek_praca_mgr/logs \
  --dump-ports s2-eth1 \
  --pcap-ifs ""

sudo -E python3 /media/sf_Gacek_praca_mgr/traffic/run_traffic.py \
  --topo-file /media/sf_Gacek_praca_mgr/mininet_topo/project_topo_3_switches.py \
  --controller-ip 127.0.0.1 --controller-port 6653 \
  --duration 60 \
  --scenario b \
  --log-dir /media/sf_Gacek_praca_mgr/logs \
  --bottleneck-dev s2-eth1 \
  --bottleneck-rate 20mbit \
  --dump-ports s2-eth1 \
  --pcap-ifs ""

T2:
sudo systemctl restart openvswitch-switch
sudo mn -c
QOS_MODE=htb ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py

Raport:

python3 plot_baseline.py   --run-dir /media/sf_Gacek_praca_mgr/logs/a_20251026_131851   --out-prefix /media/sf_Gacek_praca_mgr/logs/a_20251026_131851

python3 analyze_baseline.py   --run-dir /media/sf_Gacek_praca_mgr/logs/a_20251026_131851   --out-dir /media/sf_Gacek_praca_mgr/logs/a_20251026_131851

python3 b_analyze_diffserv_htb.py   --run-dir /media/sf_Gacek_praca_mgr/logs/b_20251028_204151 --out-dir /media/sf_Gacek_praca_mgr/logs/b_20251028_204151

A. Baseline (BEZ QoS)
    -cel: pokazać, że samo ustawienie DSCP w pakietach bez kolejek/meters nie daje priorytetu. Wszystkie klasy konkurują Best-Effort.
    -co zmierze:
        -Throughput per strumień/Jitter/packet loss + RTT/jitter RTT (ping/fping) — żeby mieć punkt odniesienia.
    -co weryfikuje:
        -przy sumarycznym obciążeniu zbliżonym/przekraczającym bottleneck wszystkie klasy tracą podobnie, EF nie „wygrywa” (bo nie ma jeszcze kolejek ani reguł).
        -widać wzrost jitter/loss dla wszystkich przy nasyceniu

B. DiffServ + kolejki (HTB) — Shaping / priorytety na wąskim gardle
    -cel: wymusić priorytety między klasami. EF powinien utrzymywać niski jitter/stratę przy przeciążeniu łącza, AF „średnio”, BE „reszta”
    -co zmierze: throughput/jitter/loss per klasa + RTT oraz statystyki kolejek (zajętość/dropy) na porcie „wąskim”
    -co weryfikuje:
        -Poziom pakietów: widze reguły z ip_dscp i set_queue - to potwierdza klasyfikację
        -Poziom kolejek - liczniki bajtów/pkt i dropów w q1/q2/q0; EF powinien mieć najmniej dropów i stabilny transfer/jitter
        -Poziom aplikacyjny - w iperf3 EF utrzymuje zadany bitrate z niskim jitterem; AF dostaje przydział wg HTB, BE traci najwięcej przy przepełnieniu.

C. Policing (OpenFlow meters) — cięcie nadmiaru, nie zmiana trasy
    -cel: pokazać różnicę między shapingiem (kolejki buforują/gładzą) a policingiem (twardy limit: nadmiar drop/remark).
    -co zmierze: throughput/packet loss +RTT pomocniczo
    -co weryfikuje:
        -throughput AF „przytnie” do limitu, a loss wzrośnie dla nadmiaru
        -brak zmiany trasy - sprawdze dump-flows — policer nie wprowadza OUTPUT na inny port
        -kolejki mogą raportować mniej dropów (bo nadmiar został odcięty wcześniej przez meter).

D. DiffServ + MPLS (push/pop + EXP) i tryby tunelowania
    -cel:zademonstrować mapowanie DSCP↔EXP (mpls_tc) i trzy tryby: Uniform, Short-Pipe, Pipe. Warstwa MPLS nie musi „polepszyć” samych metryk jakości — ona przenosi klasę w rdzeniu i pozwala na polityki w core.
    -co zmierze:
        -oprawność oznakowania
        -zachowanie trybów: czy po wyjściu z tunelu DSCP wraca (Uniform), pozostaje oryginalny (Short-Pipe), albo jest niezależny (Pipe).
    -co weryfikuje:
        -pcap/Wireshark: na wejściu widzisz MPLS (ethertype 0x8847) i mpls.tc zgodny z DSCP → (np. EF→EXP 5/7, AF→3, BE→0).
        -tryby unform/short-pipe/pipe

E. Selekcja ścieżek per klasa (SDN routing) + awaria
    -cel:rozdzielić klasy na różne ścieżki (np. EF krótszą s1–s2, AF/BE przez s3) i/lub dodać Fast-Failover dla EF
    -co zmierze:
        -ping 
        -stabilność throughput EF względem AF/BE
        -czas rekonwergencji po awarii linku
    -co weryfikuje:
        -dump-flows - różne OUTPUT:port dla różnych ip_dscp na tych samych switchach.
        -rtt -  EF ma niższe RTT od AF/BE.
        -awaria: po down’ie linku (np. link s1 s2 down w Mininecie) EF przełącza się < 1 s (z group FF) lub po przeinstalowaniu flowów przez Ryu.