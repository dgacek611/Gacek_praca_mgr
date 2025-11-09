# Scenario B — DiffServ + HTB report (2025-11-09 13:31:01)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 38.607 | 0.466 | 0.293
AF31 | 28.913 | 0.500 | 0.293
BE | 9.678 | 1.315 | 0.277

## Ping (h1→h2)
- Packet loss: 0.33%
- RTT min/avg/max/mdev: 36.120 / 119.080 / 163.881 / 17.304 ms

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
sp1-eth2_qos.txt | 1 | 75471 | 112450346 | None | 0
sp1-eth2_qos.txt | 2 | 100595 | 149885106 | None | 0

**Uwaga**: Scenariusz B: oczekujemy priorytetów i kształtowania (HTB) + prawidłowej klasyfikacji DSCP→kolejki.
