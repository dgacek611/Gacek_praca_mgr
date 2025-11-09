# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 20.568 | 1.036 | 48.312
AF31 | 36.889 | 1.580 | 7.325
BE | 38.557 | 2.945 | 2.999

## Ping (h1→h2)
- Packet loss: 10.33%
- RTT min/avg/max/mdev: 38.041 / 153.034 / 206.306 / 16.997 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
