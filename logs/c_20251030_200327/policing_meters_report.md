# Scenario C — Policing (OpenFlow meters) report (2025-10-30 20:49:04)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 5.847 | 0.027 | 51.276
AF31 | 2.931 | 0.069 | 51.144
BE | 0.989 | 0.292 | 50.516

## Ping (h1→h2)
- Packet loss: 0.85%
- RTT min/avg/max/mdev: 0.034 / 0.058 / 0.673 / 0.037 ms

## Kontrole w Table 0 (OVS flows)
- Reguły w Table 0 obecne: **True**
- InstructionMeter w Table 0: **True**
- SetQueue w Table 0 (oznaka trybu kolejkowania, NIE policing): **False**
- OUTPUT w Table 0 (niepożądane): **False**
Plik | table0_rules | table0_with_meter | table0_with_set_queue | table0_with_output
---|---:|---:|---:
s3_flows.txt | 5 | 0 | 0 | 0
s2_flows.txt | 8 | 3 | 0 | 0
s1_flows.txt | 5 | 0 | 0 | 0

## Statystyki meterów (dump-meters + dump-meter-stats)
- Zrzuty metery obecne: **True**
Plik | meter_id | rate_kbps | burst_kb | drops_pkts | drops_bytes
---|---:|---:|---:|---:|---:
s3_meters.txt |  |  |  |  | 
s2_meters.txt | 1 | 6000 | 1000 | 31870 | 47486300
s2_meters.txt | 2 | 3000 | 1000 | 15894 | 23682060
s2_meters.txt | 3 | 1000 | 2000 | 5245 | 7822334
s1_meters.txt |  |  |  |  | 

**Uwaga**: Scenariusz C: oczekujemy InstructionMeter w Table 0 i OUTPUT dopiero w Table 1; metery powinny raportować dropy przy przekroczeniu rate.
