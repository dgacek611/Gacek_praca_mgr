# Scenario B — DiffServ + HTB report (2025-10-30 19:46:30)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 5.776 | 2.256 | 0.000
AF31 | 2.899 | 4.554 | 0.000
BE | 0.964 | 13.959 | 0.000

## Ping (h1→h2)
- Packet loss: 0.00%
- RTT min/avg/max/mdev: 0.000 / 782.634 / 1118.000 / 256.803 ms

## Kontrole klasyfikacji (OVS flows)
- HTB obecny: **False**
- set_queue w flowach: **True**
- Dopasowania DSCP w flowach: **True**

Plik | ip_dscp(any) | EF(dscp=46) | AF31(dscp=26) | set_queue:0 | :1 | :2 | set_field->ip_dscp | meter
---|---:|---:|---:|---:|---:|---:|---:|---:
s1_flows.txt | 3 | 1 | 1 | 1 | 1 | 1 | 0 | 0
s2_flows.txt | 3 | 1 | 1 | 1 | 1 | 1 | 0 | 0
s3_flows.txt | 3 | 1 | 1 | 1 | 1 | 1 | 0 | 0

## Statystyki HTB (tc -s) na interfejsach „wąskiego gardła”
Plik/klasa | parent | prio | rate | ceil | bytes | pkts | drops | overlimits | backlog(B) | backlog(pkts)
---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:
**s2-eth1_tc.txt** |  |  |  |  |  |  |  |  |  | 

## Statystyki OVS QoS/queues (opcjonalne)
Plik | queue | packets | bytes | dropped | errors
---|---:|---:|---:|---:|---:
s2-eth1_qos.txt | 1 | 15181 | 22618246 | None | 0
s2-eth1_qos.txt | 2 | 30254 | 45077016 | None | 0

**Uwaga**: Scenariusz B: oczekujemy priorytetów i kształtowania (HTB) + prawidłowej klasyfikacji DSCP→kolejki.
