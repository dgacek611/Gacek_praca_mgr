# Scenario B — DiffServ + HTB report (2025-11-09 13:31:01)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 38.621 | 0.414 | 0.315
AF31 | 28.988 | 0.467 | 0.307
BE | 9.676 | 1.494 | 0.313

## Ping (h1→h2)
- Packet loss: 0.67%
- RTT min/avg/max/mdev: 33.625 / 119.503 / 148.783 / 17.451 ms

## Kontrole klasyfikacji (OVS flows)
- HTB obecny: **False**
- set_queue w flowach: **True**
- Dopasowania DSCP w flowach: **True**

Plik | ip_dscp(any) | EF(dscp=46) | AF31(dscp=26) | set_queue:0 | :1 | :2 | set_field->ip_dscp | meter
---|---:|---:|---:|---:|---:|---:|---:|---:
s11_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
sp1_flows.txt | 3 | 1 | 1 | 1 | 1 | 1 | 0 | 0
sp2_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s6_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s2_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s10_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s4_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s7_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s5_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s8_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s9_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s3_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s1_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0
s12_flows.txt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0

## Statystyki HTB (tc -s) na interfejsach „wąskiego gardła”
Plik/klasa | parent | prio | rate | ceil | bytes | pkts | drops | overlimits | backlog(B) | backlog(pkts)
---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:
**sp1-eth2_tc.txt** |  |  |  |  |  |  |  |  |  | 

## Statystyki OVS QoS/queues (opcjonalne)
Plik | queue | packets | bytes | dropped | errors
---|---:|---:|---:|---:|---:
htb_qos.txt | 1 | 0 | 0 | None | 0
htb_qos.txt | 2 | 0 | 0 | None | 0
sp1-eth2_qos.txt | 1 | 75610 | 112657456 | None | 0
sp1-eth2_qos.txt | 2 | 100762 | 150133936 | None | 0

**Uwaga**: Scenariusz B: oczekujemy priorytetów i kształtowania (HTB) + prawidłowej klasyfikacji DSCP→kolejki.
