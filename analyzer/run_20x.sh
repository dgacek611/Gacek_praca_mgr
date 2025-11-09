#!/bin/bash

for i in {1..20}; do
  echo "=============================="
  echo "Uruchamiam bieg $i / 20"
  echo "=============================="

  sudo -E python3 /home/dorota/Gacek_praca_mgr/traffic/run_traffic_polska.py \
    --topo-file /home/dorota/Gacek_praca_mgr/mininet_topo/polska_topo.py \
    --controller-ip 127.0.0.1 --controller-port 6653 \
    --duration 30 \
    --scenario c \
    --bottleneck-dev sp1-eth2 \
    --log-dir /home/dorota/Gacek_praca_mgr/logs/scenario_C

done
