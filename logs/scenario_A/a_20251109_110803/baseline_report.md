# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 20.526 | 1.272 | 48.414
AF31 | 37.223 | 1.337 | 6.465
BE | 37.976 | 2.097 | 4.587

## Ping (h1→h2)
- Packet loss: 8.33%
- RTT min/avg/max/mdev: 39.311 / 154.027 / 202.847 / 15.464 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
