# Analiza możliwości wykorzystania koncepcji SDN do dynamicznej kontroli QoS w sieciach opartych na MPLS i DiffServ

1. START VM

		sudo modprobe -a openvswitch sch_htb sch_netem sch_hfsc sch_tbf sch_red
		sudo /etc/init.d/openvswitch-switch start
		pyenv activate sdn

2. KONTROLER

		sudo systemctl restart openvswitch-switch
		sudo mn -c

	A) 
	
		QOS_MODE=none ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py

		QOS_MODE=none ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_qos.py

	B)
	
		QOS_MODE=htb ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py

		QOS_MODE=htb ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_qos.py
	
	C)
	
		QOS_MODE=meter ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py

		QOS_MODE=meter ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_qos.py

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

		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--duration 30 \
			--scenario a \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_A
  
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

		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--duration 30 \
			--scenario b \
			--bottleneck-dev sp1-eth2 \
			--verify-htb \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_B

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

		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--duration 30 \
			--scenario c \
			--bottleneck-dev sp1-eth2 \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_C


4. PLAN:

A) Baseline (BEZ QoS)

-cel: pokazać, że samo ustawienie DSCP w pakietach bez kolejek/meters nie daje priorytetu. Wszystkie klasy konkurują Best-Effort.
-co zmierze:
	-Throughput per strumień/Jitter/packet loss
-co weryfikuje:
	-przy sumarycznym obciążeniu zbliżonym/przekraczającym bottleneck wszystkie klasy tracą podobnie, EF nie „wygrywa” (bo nie ma jeszcze kolejek ani reguł).
	-widać wzrost jitter/loss dla wszystkich przy nasyceniu

B1) DiffServ + kolejki (HTB) — Shaping / priorytety na wąskim gardle

-cel: wymusić priorytety między klasami. EF powinien utrzymywać niski jitter/stratę przy przeciążeniu łącza, AF „średnio”, BE „reszta”
-co zmierze: throughput/jitter/loss per klasa 
-co weryfikuje:
	-Poziom pakietów: widze reguły z ip_dscp i set_queue - to potwierdza klasyfikację
	-Poziom kolejek - liczniki bajtów/pkt i dropów w q1/q2/q0; EF powinien mieć najmniej dropów i stabilny transfer/jitter
	-Poziom aplikacyjny - w iperf3 EF utrzymuje zadany bitrate z niskim jitterem; AF dostaje przydział wg HTB, BE traci najwięcej przy przepełnieniu.

C) Policing (OpenFlow meters) — cięcie nadmiaru, nie zmiana trasy

-cel: pokazać różnicę między shapingiem (kolejki buforują/gładzą) a policingiem (twardy limit: nadmiar drop/remark).
-co zmierze: throughput/packet loss
-co weryfikuje:
	-throughput AF „przytnie” do limitu, a loss wzrośnie dla nadmiaru

D) DiffServ + MPLS (push/pop + EXP) i tryby tunelowania

-cel: zademonstrować mapowanie DSCP↔EXP (mpls_tc) i trzy tryby: Uniform, Short-Pipe, Pipe. Warstwa MPLS nie musi „polepszyć” samych metryk jakości — ona przenosi klasę w rdzeniu i pozwala na polityki w core.
-co zmierze:
	-poprawność oznakowania
	-zachowanie trybów: czy po wyjściu z tunelu DSCP wraca (Uniform), pozostaje oryginalny (Short-Pipe), albo jest niezależny (Pipe).
-co weryfikuje:
	-pcap/Wireshark: na wejściu widzisz MPLS (ethertype 0x8847) i mpls.tc zgodny z DSCP → (np. EF→EXP 5/7, AF→3, BE→0).
	-tryby unform/short-pipe/pipe

E) Selekcja ścieżek per klasa (SDN routing) + awaria

-cel: rozdzielić klasy na różne ścieżki i dodać Fast-Failover dla EF
-co weryfikuje:
	-dump-flows - różne OUTPUT:port dla różnych ip_dscp na tych samych switchach.
	-rtt -  EF ma niższe RTT od AF/BE.
	-awaria: po down’ie linku (np. link s1 s2 down w Mininecie) EF przełącza się < 1 s (z group FF) lub po przeinstalowaniu flowów przez Ryu.

5. ANALIZA:
	sudo chown -R dorota:dorota /home/dorota/Gacek_praca_mgr/logs/scenario_B

	A) 
	
		python3 analyze_baseline.py --run-dir /home/dorota/Gacek_praca_mgr/logs/scenario_A/a_20251109_112041

		python3 analyze_baseline.py --runs-root /home/dorota/Gacek_praca_mgr/logs/scenario_A

		python plot_baseline.py --csv /home/dorota/Gacek_praca_mgr/logs/scenario_A/all_runs_summary_rx.csv --out-prefix /home/dorota/Gacek_praca_mgr/logs/scenario_A/plots


	B)
	
		python3 b_analyze_diffserv_htb.py --run-dir /home/dorota/Gacek_praca_mgr/logs/scenario_B/b_20251109_112041

		python3 b_analyze_diffserv_htb.py --runs-root /home/dorota/Gacek_praca_mgr/logs/scenario_B

		python b_plot_diffserv_htb.py --csv /home/dorota/Gacek_praca_mgr/logs/scenario_B/all_runs_summary_rx.csv --out-prefix /home/dorota/Gacek_praca_mgr/logs/scenario_B/plots

	C)
	
		python3 c_analyze_meters.py --run-dir /home/dorota/Gacek_praca_mgr/logs/scenario_C/c_20251109_112041

		python3 c_analyze_meters.py --runs-root /home/dorota/Gacek_praca_mgr/logs/scenario_C

		python c_plot_meters.py --csv /home/dorota/Gacek_praca_mgr/logs/scenario_C/all_runs_summary_rx.csv --out-prefix /home/dorota/Gacek_praca_mgr/logs/scenario_C/plots

6. WYNIKI:

Topologia: bw=100 Mb/s na wszystkich linkach.

Ruch w A, B i C: zawsze 3 strumienie UDP

EF 40 Mb/s, AF 40 Mb/s, BE 40 Mb/s (łącznie 120 Mb/s).

Wnioski:

	A) pokaż, że mimo różnych DSCP wszystkie klasy zachowują się jak BE, link 100 Mb/s, offered 120 Mb/s -> wszystkie trzy klasy wchodzą w konkurencję Best Effort, DSCP jest ustawione, ale brak kolejek/metrów, więc metryki (throughput/jitter/loss) powinny być podobne dla wszystkich przy nasyceniu.

	B) przy tym samym ruchu pojawiają się priorytety (kolejki HTB),	dalej te same 3×40 Mb/s, na bottlenecku HTB: EF - gwarantowane 40 Mb/s, AF - min 20 Mb/s, BE - reszta / best-effort, wtedy w przeciążeniu widać wyraźnie, że EF trzyma parametry, AF „średnio”, a BE obrywa najbardziej – a ruch generujący jest identyczny jak w A.

	C) przy tym samym ruchu widać różnicę „shaping vs policing”, znów te same 3×40 Mb/s, na EF meter 40 Mb/s CIR, EF ma throughput „przycięty” do ~40 Mb/s, AF -> 30 Mb/s, BE -> 10 Mb/s