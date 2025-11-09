# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 38.431 | 1.145 | 3.417
AF31 | 20.704 | 0.985 | 47.967
BE | 36.755 | 1.490 | 7.647

## Ping (h1→h2)
- Packet loss: 8.33%
- RTT min/avg/max/mdev: 41.517 / 153.493 / 201.556 / 14.887 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
