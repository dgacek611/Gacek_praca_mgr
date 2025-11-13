# Analiza możliwości wykorzystania koncepcji SDN do dynamicznej kontroli QoS w sieciach opartych na MPLS i DiffServ

1. START VM

		sudo modprobe -a openvswitch sch_htb sch_netem sch_hfsc sch_tbf sch_red
		sudo /etc/init.d/openvswitch-switch start
		pyenv activate sdn

2. SCENARIUSZE

A) Baseline (BEZ QoS)

B) Traffic Shaping - DiffServ + kolejki (HTB) 

C) Traffic Policing (OpenFlow meters) 

D) DiffServ + MPLS (push/pop + EXP) i tryby tunelowania

E) Selekcja ścieżek per klasa (SDN routing) + Fast_Failover

3. KONTROLER

		sudo systemctl restart openvswitch-switch
		sudo mn -c

	A) 
	
		QOS_MODE=none ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_qos.py

	B)
	
		QOS_MODE=htb ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_qos.py
	
	C)
	
		QOS_MODE=meter ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_qos.py

	D) 
	
		MPLS_MODE=uniform ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_mpls.py

	E)  
	
		MPLS_MODE=pipe  ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /home/dorota/Gacek_praca_mgr/ryu_app/ryu_FF_mpls.py

4. SIEĆ I RUCH

	A)

		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--duration 30 \
			--scenario a \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_A
  
	B)

		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--duration 30 \
			--scenario b \
			--bottleneck-dev sp1-eth2 \
			--verify-htb \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_B

	C)

		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--duration 30 \
			--scenario c \
			--bottleneck-dev sp1-eth2 \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_C

	D) 

 		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--duration 30\
			--scenario a \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_D_short_pipe \
			--pcap-ifs "sp1-eth1,sp1-eth2,sp2-eth2,sp2-eth1,s1-eth3,s1-eth2,s1-eth1"

	E) 
	
		sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_FF.py \
			--topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
			--controller-ip 127.0.0.1 --controller-port 6653 \
			--fail-link s1,s6 \
			--fail-at 10 \
			--fail-up-after 10 \
			--ef-mbit 40 \
			--af-mbit 40 \
			--be-mbit 40 \
			--scenario a \
			--log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_E

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