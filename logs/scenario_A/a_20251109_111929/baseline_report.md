# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 20.247 | 1.338 | 49.121
AF31 | 38.794 | 1.381 | 2.520
BE | 37.118 | 1.297 | 6.726

## Ping (h1→h2)
- Packet loss: 16.67%
- RTT min/avg/max/mdev: 39.748 / 153.085 / 190.504 / 15.112 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
