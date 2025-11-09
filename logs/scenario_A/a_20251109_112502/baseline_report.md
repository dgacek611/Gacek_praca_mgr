# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 37.688 | 1.463 | 5.280
AF31 | 31.934 | 1.083 | 19.749
BE | 25.899 | 1.393 | 34.921

## Ping (h1→h2)
- Packet loss: 12.67%
- RTT min/avg/max/mdev: 42.275 / 154.339 / 220.747 / 15.937 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
