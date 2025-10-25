# Analiza możliwości wykorzystania koncepcji SDN do dynamicznej kontroli QoS w sieciach opartych na MPLS i DiffServ

T1:
sudo -E python3 /media/sf_Gacek_praca_mgr/traffic/run_traffic.py --topo-file /media/sf_Gacek_praca_mgr/mininet_topo/project_topo_3_switches.py --duration 30

T2:
sudo systemctl restart openvswitch-switch
sudo mn -c
ryu-manager --verbose --observe-links --ofp-tcp-listen-port 6653 /media/sf_Gacek_praca_mgr/ryu_app/qos_ryu.py