# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 38.459 | 1.392 | 3.330
AF31 | 29.232 | 1.337 | 26.525
BE | 27.884 | 1.392 | 29.917

## Ping (h1→h2)
- Packet loss: 6.33%
- RTT min/avg/max/mdev: 40.401 / 154.077 / 212.592 / 16.542 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
