package analyzer

import (
	"testing"

	"github.com/miekg/dns"
)

func TestFormatSOAMboxAndParseSOA(t *testing.T) {
	got := FormatSOAMbox("dns-admin.google.com.")
	if got != "dns-admin@google.com" {
		t.Errorf("FormatSOAMbox = %q, want %q", got, "dns-admin@google.com")
	}

	rr := &dns.SOA{
		Ns:      "ns1.cloudflare.com.",
		Mbox:    "dns.cloudflare.com.",
		Serial:  2026103101,
		Refresh: 10000,
		Retry:   2400,
		Expire:  604800,
		Minttl:  3600,
	}
	soa := ParseSOARecord(rr)
	if soa.PrimaryNS != "ns1.cloudflare.com" || soa.AdminEmail != "dns@cloudflare.com" || soa.Serial != 2026103101 {
		t.Errorf("unexpected parsed SOA: %+v", soa)
	}
}

func TestEvaluateDNSSECStatus(t *testing.T) {
	// 1. Fully signed & validated
	ds := []DSRecordInfo{{KeyTag: 2371, Algorithm: 13, AlgoName: "ECDSAP256SHA256 (13)", DigestType: 2, DigestName: "SHA-256 (2)", Digest: "AABBCC"}}
	keys := []DNSKEYRecordInfo{{Role: "KSK (257)", Flags: 257, KeyTag: 2371, Algorithm: 13, AlgoName: "ECDSAP256SHA256 (13)"}}
	enabled, status, _ := EvaluateDNSSECStatus(ds, keys, 2, true)
	if !enabled || status != "Secure (Signed & Validated)" {
		t.Errorf("expected Secure (Signed & Validated), got enabled=%v status=%q", enabled, status)
	}

	// 2. Incomplete (DNSKEY without parent DS)
	enabled, status, _ = EvaluateDNSSECStatus(nil, keys, 1, false)
	if enabled || status != "Incomplete (Missing Parent DS)" {
		t.Errorf("expected Incomplete (Missing Parent DS), got enabled=%v status=%q", enabled, status)
	}

	// 3. Broken Chain (DS without DNSKEY)
	enabled, status, _ = EvaluateDNSSECStatus(ds, nil, 0, false)
	if enabled || status != "Broken Chain (DS Without DNSKEY)" {
		t.Errorf("expected Broken Chain (DS Without DNSKEY), got enabled=%v status=%q", enabled, status)
	}

	// 4. Unsigned
	enabled, status, _ = EvaluateDNSSECStatus(nil, nil, 0, false)
	if enabled || status != "Unsigned" {
		t.Errorf("expected Unsigned, got enabled=%v status=%q", enabled, status)
	}
}

func TestFormatDNSSECAlgorithmAndDigest(t *testing.T) {
	if got := FormatDNSSECAlgorithm(13); got != "ECDSAP256SHA256 (13)" {
		t.Errorf("FormatDNSSECAlgorithm(13) = %q", got)
	}
	if got := FormatDNSSECAlgorithm(15); got != "ED25519 (15)" {
		t.Errorf("FormatDNSSECAlgorithm(15) = %q", got)
	}
	if got := FormatDSDigestType(2); got != "SHA-256 (2)" {
		t.Errorf("FormatDSDigestType(2) = %q", got)
	}
}
