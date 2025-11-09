# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 35.364 | 1.417 | 11.129
AF31 | 38.965 | 1.535 | 2.092
BE | 21.721 | 1.044 | 45.415

## Ping (h1→h2)
- Packet loss: 8.00%
- RTT min/avg/max/mdev: 41.742 / 156.552 / 199.045 / 15.861 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
