# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 36.644 | 1.376 | 7.920
AF31 | 34.037 | 1.535 | 14.464
BE | 25.367 | 1.413 | 36.256

## Ping (h1→h2)
- Packet loss: 27.33%
- RTT min/avg/max/mdev: 39.750 / 152.545 / 229.896 / 20.877 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
