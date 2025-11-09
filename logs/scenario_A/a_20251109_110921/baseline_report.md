# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 23.058 | 1.347 | 42.056
AF31 | 34.187 | 1.356 | 14.086
BE | 38.296 | 1.141 | 3.770

## Ping (h1→h2)
- Packet loss: 10.33%
- RTT min/avg/max/mdev: 40.514 / 154.551 / 225.605 / 16.830 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
