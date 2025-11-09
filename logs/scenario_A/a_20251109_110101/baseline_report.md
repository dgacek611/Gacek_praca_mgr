# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 21.361 | 2.035 | 46.245
AF31 | 38.192 | 1.371 | 4.019
BE | 36.280 | 1.090 | 8.829

## Ping (h1→h2)
- Packet loss: 7.00%
- RTT min/avg/max/mdev: 40.415 / 153.471 / 195.398 / 16.140 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
