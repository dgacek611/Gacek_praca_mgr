# Scenario A — Baseline report (2025-11-09 11:28:00)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 21.224 | 1.505 | 46.656
AF31 | 36.175 | 1.587 | 9.093
BE | 38.642 | 1.098 | 2.889

## Ping (h1→h2)
- Packet loss: 20.33%
- RTT min/avg/max/mdev: 39.559 / 152.801 / 202.774 / 17.016 ms

## Kontrole poprawności
- TBF obecny: **True** (sp1-eth2)
- Brak reguł QoS (ip_dscp/set_queue/meter) w dump-flows: **True**
- Uwaga: W scenariuszu A brak priorytetów – wszystkie klasy konkurują Best-Effort.
