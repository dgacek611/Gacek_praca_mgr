# Scenario A — Baseline report (2025-10-30 19:44:37)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 2.674 | 0.308 | 55.391
AF31 | 2.899 | 0.298 | 51.630
BE | 4.140 | 0.648 | 30.926

## Ping (h1→h2)
- Packet loss: 0.00%
- RTT min/avg/max/mdev: 0.057 / 62.574 / 76.085 / 11.339 ms

## Kontrole poprawności
- TBF obecny: **True** (s2-eth1)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
