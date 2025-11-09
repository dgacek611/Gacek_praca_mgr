# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 30.694 | 1.334 | 22.853
AF31 | 35.955 | 1.759 | 9.653
BE | 26.421 | 1.167 | 33.595

## Ping (h1→h2)
- Packet loss: 15.67%
- RTT min/avg/max/mdev: 40.726 / 159.076 / 342.130 / 31.379 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
