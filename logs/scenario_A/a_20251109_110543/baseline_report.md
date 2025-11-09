# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 22.256 | 1.128 | 44.066
AF31 | 33.544 | 1.813 | 15.714
BE | 35.577 | 1.255 | 10.596

## Ping (h1→h2)
- Packet loss: 13.67%
- RTT min/avg/max/mdev: 40.093 / 162.090 / 267.642 / 27.407 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
