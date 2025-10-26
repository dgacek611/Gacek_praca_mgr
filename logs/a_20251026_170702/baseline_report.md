# Scenario A — Baseline report (2025-10-26 16:09:36)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 7.304 | 5.365 | 62.284
AF31 | 6.704 | 8.939 | 66.309
BE | 7.253 | 10.795 | 63.415

## Ping (h1→h2)
- Packet loss: 9.83%
- RTT min/avg/max/mdev: 0.057 / 1.701 / 138.808 / 9.997 ms

## Kontrole poprawności
- TBF obecny: **False**
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
