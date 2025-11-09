# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 20.973 | 1.299 | 47.298
AF31 | 38.104 | 1.108 | 4.235
BE | 37.614 | 1.217 | 5.475

## Ping (h1→h2)
- Packet loss: 11.00%
- RTT min/avg/max/mdev: 39.653 / 152.304 / 161.006 / 13.442 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
