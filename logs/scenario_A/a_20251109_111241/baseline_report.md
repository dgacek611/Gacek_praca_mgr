# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 32.713 | 1.585 | 17.783
AF31 | 26.799 | 1.075 | 32.643
BE | 34.931 | 1.356 | 12.210

## Ping (h1→h2)
- Packet loss: 14.67%
- RTT min/avg/max/mdev: 37.837 / 156.096 / 246.402 / 21.157 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
