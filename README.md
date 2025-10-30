# Analiza możliwości wykorzystania koncepcji SDN do dynamicznej kontroli QoS w sieciach opartych na MPLS i DiffServ

1. START VM

	source mgr_sdn/bin/activate
	
	sudo mount -t vboxsf Gacek_praca_mgr /media/sf_Gacek_praca_mgr

2. KONTROLER

	sudo systemctl restart openvswitch-switch
	
	sudo mn -c

	A) 
	QOS_MODE=none ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py

	B)
	QOS_MODE=htb ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py
	
	C)
	QOS_MODE=meter ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py

3. SIEĆ I RUCH

	A)
	sudo -E python3 /media/sf_Gacek_praca_mgr/traffic/run_traffic.py \
	  --topo-file /media/sf_Gacek_praca_mgr/mininet_topo/project_topo_3_switches.py \
	  --controller-ip 127.0.0.1 --controller-port 6653 \
	  --duration 60 \
	  --scenario a \
	  --log-dir /media/sf_Gacek_praca_mgr/logs \
	  --dump-ports s2-eth1 \
	  --pcap-ifs ""
  
	B)
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
	  
	C)
	sudo -E python3 /media/sf_Gacek_praca_mgr/traffic/run_traffic.py \
	  --topo-file /media/sf_Gacek_praca_mgr/mininet_topo/project_topo_3_switches.py \
	  --controller-ip 127.0.0.1 --controller-port 6653 \
	  --duration 60 \
	  --scenario c \
	  --log-dir /media/sf_Gacek_praca_mgr/logs \
	  --bottleneck-dev s2-eth1 \
	  --bottleneck-rate 20mbit \
	  --dump-ports s2-eth1 \
	  --pcap-ifs ""

4. PLAN:

A) Baseline (BEZ QoS)

    -cel: pokazać, że samo ustawienie DSCP w pakietach bez kolejek/meters nie daje priorytetu. Wszystkie klasy konkurują Best-Effort.
    -co zmierze:
        -Throughput per strumień/Jitter/packet loss + RTT/jitter RTT (ping/fping) — żeby mieć punkt odniesienia.
    -co weryfikuje:
        -przy sumarycznym obciążeniu zbliżonym/przekraczającym bottleneck wszystkie klasy tracą podobnie, EF nie „wygrywa” (bo nie ma jeszcze kolejek ani reguł).
        -widać wzrost jitter/loss dla wszystkich przy nasyceniu

B) DiffServ + kolejki (HTB) — Shaping / priorytety na wąskim gardle

    -cel: wymusić priorytety między klasami. EF powinien utrzymywać niski jitter/stratę przy przeciążeniu łącza, AF „średnio”, BE „reszta”
    -co zmierze: throughput/jitter/loss per klasa + RTT oraz statystyki kolejek (zajętość/dropy) na porcie „wąskim”
    -co weryfikuje:
        -Poziom pakietów: widze reguły z ip_dscp i set_queue - to potwierdza klasyfikację
        -Poziom kolejek - liczniki bajtów/pkt i dropów w q1/q2/q0; EF powinien mieć najmniej dropów i stabilny transfer/jitter
        -Poziom aplikacyjny - w iperf3 EF utrzymuje zadany bitrate z niskim jitterem; AF dostaje przydział wg HTB, BE traci najwięcej przy przepełnieniu.

C) Policing (OpenFlow meters) — cięcie nadmiaru, nie zmiana trasy

    -cel: pokazać różnicę między shapingiem (kolejki buforują/gładzą) a policingiem (twardy limit: nadmiar drop/remark).
    -co zmierze: throughput/packet loss +RTT pomocniczo
    -co weryfikuje:
        -throughput AF „przytnie” do limitu, a loss wzrośnie dla nadmiaru
        -brak zmiany trasy - sprawdze dump-flows — policer nie wprowadza OUTPUT na inny port
        -kolejki mogą raportować mniej dropów (bo nadmiar został odcięty wcześniej przez meter).

D) DiffServ + MPLS (push/pop + EXP) i tryby tunelowania

    -cel:zademonstrować mapowanie DSCP↔EXP (mpls_tc) i trzy tryby: Uniform, Short-Pipe, Pipe. Warstwa MPLS nie musi „polepszyć” samych metryk jakości — ona przenosi klasę w rdzeniu i pozwala na polityki w core.
    -co zmierze:
        -oprawność oznakowania
        -zachowanie trybów: czy po wyjściu z tunelu DSCP wraca (Uniform), pozostaje oryginalny (Short-Pipe), albo jest niezależny (Pipe).
    -co weryfikuje:
        -pcap/Wireshark: na wejściu widzisz MPLS (ethertype 0x8847) i mpls.tc zgodny z DSCP → (np. EF→EXP 5/7, AF→3, BE→0).
        -tryby unform/short-pipe/pipe

E) Selekcja ścieżek per klasa (SDN routing) + awaria

    -cel:rozdzielić klasy na różne ścieżki (np. EF krótszą s1–s2, AF/BE przez s3) i/lub dodać Fast-Failover dla EF
    -co zmierze:
        -ping 
        -stabilność throughput EF względem AF/BE
        -czas rekonwergencji po awarii linku
    -co weryfikuje:
        -dump-flows - różne OUTPUT:port dla różnych ip_dscp na tych samych switchach.
        -rtt -  EF ma niższe RTT od AF/BE.
        -awaria: po down’ie linku (np. link s1 s2 down w Mininecie) EF przełącza się < 1 s (z group FF) lub po przeinstalowaniu flowów przez Ryu.

5. ANALIZA:

	A) 
	
		python3 analyze_baseline.py   --run-dir /media/sf_Gacek_praca_mgr/logs/a_20251030_192809   --out-dir /media/sf_Gacek_praca_mgr/logs/a_20251030_192809
		python3 plot_baseline.py   --run-dir /media/sf_Gacek_praca_mgr/logs/a_20251030_192809   --out-prefix /media/sf_Gacek_praca_mgr/logs/a_20251030_192809 --ylim-throughput 0 10 --ylim-loss 0 100 --ylim-jitter 0 50

	B)
	
		python3 b_analyze_diffserv_htb.py   --run-dir /media/sf_Gacek_praca_mgr/logs/b_20251030_194419 --out-dir /media/sf_Gacek_praca_mgr/logs/b_20251030_194419
		python3 b_plot_diffserv_htb.py --run-dir /media/sf_Gacek_praca_mgr/logs/b_20251030_194419 --out-prefix /media/sf_Gacek_praca_mgr/logs/b_20251030_194419 --ylim-throughput 0 10 --ylim-loss 0 100 --ylim-jitter 0 50
	
	C)
	
	    python3 c_analyze_meters.py --run-dir /media/sf_Gacek_praca_mgr/logs/c_20251030_200327 --out-dir /media/sf_Gacek_praca_mgr/logs/c_20251030_200327
	    python3 c_plot_meters.py --run-dir /media/sf_Gacek_praca_mgr/logs/c_20251030_200327 --out-prefix /media/sf_Gacek_praca_mgr/logs/c_20251030_200327  --ylim-throughput 0 10 --ylim-loss 0 100 --ylim-jitter 0 50

6. WYNIKI:

	A) Baseline (bez QoS)

		Bottleneck: 10 Mbit/s (TBF na porcie „wąskim”).
		Wysyłanie (h1 → h2): EF=6 Mbit/s, AF=6 Mbit/s, BE=6 Mbit/s (suma 18 > 10, celowo).
		Oczekiwane: wszystkie klasy tracą podobnie; rośnie jitter/loss; EF nie ma przewagi.

	B) DiffServ + kolejki (HTB)

		Bottleneck: 10 Mbit/s (ten sam port).
		Kolejki HTB na „wąskim” porcie (min/max):
		EF: 6/6 Mbit/s, AF: 3/3 Mbit/s, BE: 1/1 Mbit/s (priorytet EF>AF>BE).
		Wysyłanie (to samo co w A): EF=6, AF=6, BE=6 Mbit/s.
		Oczekiwane: EF trzyma 6 Mbit/s z niskim jitterem; AF ~3 Mbit/s; BE ~1 Mbit/s; dropy głównie w BE/AF; liczniki kolejek to pokażą.

	C) Policing (OpenFlow meters)
	
		(Bez kolejek kształtujących – tylko bottleneck 10 Mbit/s dla spójnych warunków).
		Metery (ENV w kontrolerze):
			QOS_MODE=meter
			QOS_EF_MBIT=6, QOS_AF_MBIT=3, QOS_BE_MBIT=1
			(opcjonalnie bursty: QOS_EF_BURST_MB=1, QOS_AF_BURST_MB=1, QOS_BE_BURST_MB=2)
		Wysyłanie EF=12 Mbit/s, AF=6 Mbit/s, BE=2 Mbit/s.
		Oczekiwane: throughput każdej klasy przycięty do 6/3/1 Mbit/s, wzrost loss ponad limitem; brak zmian trasy (dump-flows bez dodatkowych OUTPUT).
