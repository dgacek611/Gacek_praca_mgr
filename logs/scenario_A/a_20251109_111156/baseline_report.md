# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 25.933 | 1.548 | 34.667
AF31 | 36.421 | 1.690 | 8.249
BE | 32.413 | 2.594 | 18.356

## Ping (h1→h2)
- Packet loss: 13.00%
- RTT min/avg/max/mdev: 38.860 / 155.432 / 214.329 / 16.886 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
