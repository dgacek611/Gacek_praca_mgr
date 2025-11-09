# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 31.798 | 1.125 | 20.091
AF31 | 25.265 | 1.111 | 36.506
BE | 38.549 | 1.186 | 3.132

## Ping (h1→h2)
- Packet loss: 15.00%
- RTT min/avg/max/mdev: 37.559 / 153.710 / 232.176 / 18.043 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
