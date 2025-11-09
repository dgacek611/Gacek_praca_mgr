# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 33.533 | 1.478 | 15.740
AF31 | 37.776 | 1.125 | 5.071
BE | 24.821 | 1.149 | 37.626

## Ping (h1→h2)
- Packet loss: 11.33%
- RTT min/avg/max/mdev: 40.616 / 153.075 / 206.112 / 15.420 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
