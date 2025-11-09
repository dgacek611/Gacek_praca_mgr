# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 36.510 | 0.993 | 8.250
AF31 | 36.557 | 1.230 | 8.130
BE | 22.970 | 1.316 | 42.279

## Ping (h1→h2)
- Packet loss: 12.00%
- RTT min/avg/max/mdev: 42.782 / 153.175 / 196.022 / 15.292 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
