# Scenario C — Policing (OpenFlow meters) report (2025-11-09 14:14:46)

## Iperf3 per klasa (RX)
Klasa | Throughput RX [Mb/s] | Jitter [ms] | Loss [%]
---|---:|---:|---:
EF | 38.635 | 0.974 | 22.630
AF31 | 29.029 | 1.038 | 41.864
BE | 9.727 | 1.158 | 80.517

## Ping (h1→h2)
- Packet loss: 3.00%
- RTT min/avg/max/mdev: 30.966 / 38.105 / 164.746 / 14.348 ms

## Kontrole w Table 0 (OVS flows)
- Reguły w Table 0 obecne: *True*
- InstructionMeter w Table 0: *True*
- SetQueue w Table 0 (oznaka trybu kolejkowania, NIE policing): *False*
- OUTPUT w Table 0 (niepożądane): *False*
Plik | table0_rules | table0_with_meter | table0_with_set_queue | table0_with_output
---|---:|---:|---:|---:
s11_flows.txt | 5 | 0 | 0 | 0
sp1_flows.txt | 8 | 3 | 0 | 0
sp2_flows.txt | 5 | 0 | 0 | 0
s6_flows.txt | 5 | 0 | 0 | 0
s2_flows.txt | 5 | 0 | 0 | 0
s10_flows.txt | 5 | 0 | 0 | 0
s4_flows.txt | 5 | 0 | 0 | 0
s7_flows.txt | 5 | 0 | 0 | 0
s5_flows.txt | 5 | 0 | 0 | 0
s8_flows.txt | 5 | 0 | 0 | 0
s9_flows.txt | 5 | 0 | 0 | 0
s3_flows.txt | 5 | 0 | 0 | 0
s1_flows.txt | 5 | 0 | 0 | 0
s12_flows.txt | 5 | 0 | 0 | 0

## Statystyki meterów (dump-meters + dump-meter-stats)
- Zrzuty metery obecne: *True*
Plik | meter_id | rate_kbps | burst_kb | drops_pkts | drops_bytes
---|---:|---:|---:|---:|---:
s11_meters.txt |  |  |  |  | 
s8_meters.txt |  |  |  |  | 
sp2_meters.txt |  |  |  |  | 
sp1_meters.txt | 1 | 40000 | 1024 | 28987 | 43190630
sp1_meters.txt | 2 | 30000 | 1024 | 53966 | 80409340
sp1_meters.txt | 3 | 10000 | 2048 | 104194 | 155239316
s7_meters.txt |  |  |  |  | 
s10_meters.txt |  |  |  |  | 
s2_meters.txt |  |  |  |  | 
s1_meters.txt |  |  |  |  | 
s4_meters.txt |  |  |  |  | 
s5_meters.txt |  |  |  |  | 
s9_meters.txt |  |  |  |  | 
s3_meters.txt |  |  |  |  | 
s12_meters.txt |  |  |  |  | 
s6_meters.txt |  |  |  |  | 

*Uwaga*: Scenariusz C: oczekujemy InstructionMeter w Table 0 i OUTPUT dopiero w Table 1; metery powinny raportować dropy przy przekroczeniu rate.
