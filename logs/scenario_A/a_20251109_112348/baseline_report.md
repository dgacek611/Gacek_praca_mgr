# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 19.559 | 1.275 | 50.842
AF31 | 37.899 | 1.206 | 4.752
BE | 38.399 | 1.503 | 3.498

## Ping (h1→h2)
- Packet loss: 13.33%
- RTT min/avg/max/mdev: 41.753 / 154.388 / 227.369 / 17.021 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
