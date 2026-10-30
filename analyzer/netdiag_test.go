package analyzer

import (
	"testing"
)

func TestParsePingOutput(t *testing.T) {
	raw := `PING example.com (93.184.216.34) 56(84) bytes of data.
64 bytes from 93.184.216.34: icmp_seq=1 ttl=57 time=11.4 ms
64 bytes from 93.184.216.34: icmp_seq=2 ttl=57 time=12.6 ms
64 bytes from 93.184.216.34: icmp_seq=3 ttl=57 time=11.8 ms
64 bytes from 93.184.216.34: icmp_seq=4 ttl=57 time=12.2 ms

--- example.com ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 904ms`

	res := ParsePingOutput(raw, "example.com", "")
	if !res.Reachable {
		t.Fatalf("expected Reachable = true")
	}
	if res.ResolvedIP != "93.184.216.34" {
		t.Errorf("expected ResolvedIP = 93.184.216.34, got %s", res.ResolvedIP)
	}
	if res.PacketsSent != 4 || res.PacketsRecv != 4 || res.LossPercent != 0 {
		t.Errorf("unexpected packet stats: sent=%d recv=%d loss=%.1f", res.PacketsSent, res.PacketsRecv, res.LossPercent)
	}
	if res.MinRTT != "11.40 ms" || res.MaxRTT != "12.60 ms" || res.AvgRTT != "12.00 ms" {
		t.Errorf("unexpected RTT stats: min=%s avg=%s max=%s", res.MinRTT, res.AvgRTT, res.MaxRTT)
	}
}

func TestParseTracerouteAndTracepathAndMTR(t *testing.T) {
	traceRaw := `traceroute to 93.184.216.34 (93.184.216.34), 20 hops max, 60 byte packets
 1  192.168.1.1  0.842 ms
 2  * * *
 3  93.184.216.34  14.210 ms`

	hops := ParseTracerouteOutput(traceRaw)
	if len(hops) != 3 {
		t.Fatalf("expected 3 traceroute hops, got %d", len(hops))
	}
	if hops[0].Hop != 1 || hops[0].IP != "192.168.1.1" || hops[0].RTT != "0.842 ms" {
		t.Errorf("unexpected hop 1: %+v", hops[0])
	}
	if !hops[1].Timeout {
		t.Errorf("expected hop 2 to be Timeout, got %+v", hops[1])
	}
	if hops[2].Hop != 3 || hops[2].IP != "93.184.216.34" {
		t.Errorf("unexpected hop 3: %+v", hops[2])
	}

	tracepathRaw := ` 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                                              0.612ms
 1:  10.0.0.1                                              0.540ms
 2:  no reply
 3:  93.184.216.34                                        12.310ms reached
     Resume: pmtu 1500 hops 3 back 3`

	tpHops := ParseTracepathOutput(tracepathRaw)
	if len(tpHops) != 3 {
		t.Fatalf("expected 3 deduplicated tracepath hops, got %d: %+v", len(tpHops), tpHops)
	}
	if tpHops[0].IP != "10.0.0.1" || tpHops[1].Timeout != true || tpHops[2].IP != "93.184.216.34" {
		t.Errorf("unexpected tracepath hops: %+v", tpHops)
	}

	mtrRaw := `Start: 2026-10-31T10:00:00+1300
HOST: workstation                 Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 192.168.1.1                0.0%     1    0.7   0.7   0.7   0.7   0.0
  2.|-- ???                       100.0     1    0.0   0.0   0.0   0.0   0.0
  3.|-- 93.184.216.34              0.0%     1   11.9  11.9  11.9  11.9   0.0`

	mtrHops := ParseMTRReportOutput(mtrRaw)
	if len(mtrHops) != 3 {
		t.Fatalf("expected 3 mtr hops, got %d", len(mtrHops))
	}
	if mtrHops[0].IP != "192.168.1.1" || !mtrHops[1].Timeout || mtrHops[2].IP != "93.184.216.34" {
		t.Errorf("unexpected mtr hops: %+v", mtrHops)
	}
}

