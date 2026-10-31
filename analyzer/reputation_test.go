package analyzer

import (
	"testing"
)

func TestReverseIPv4ForDNSBL(t *testing.T) {
	rev, ok := ReverseIPv4ForDNSBL("93.184.216.34")
	if !ok || rev != "34.216.184.93" {
		t.Errorf("ReverseIPv4ForDNSBL(93.184.216.34) = (%q, %v), want (34.216.184.93, true)", rev, ok)
	}

	if _, ok := ReverseIPv4ForDNSBL("2606:2800:220:1:248:1893:25c8:1946"); ok {
		t.Errorf("expected IPv6 address to return false for ReverseIPv4ForDNSBL")
	}
}

func TestIsValidDNSBLListing(t *testing.T) {
	// 1. Valid Spamhaus SBL listing (127.0.0.2)
	listed, codes, reason := IsValidDNSBLListing("zen.spamhaus.org", []string{"127.0.0.2"}, []string{"https://www.spamhaus.org/sbl/query/SBL1234"})
	if !listed || len(codes) != 1 || codes[0] != "127.0.0.2" {
		t.Errorf("expected valid SBL listing, got listed=%v codes=%v reason=%q", listed, codes, reason)
	}

	// 2. Administrative open-resolver error code (127.255.255.254) must be ignored
	listed, _, _ = IsValidDNSBLListing("zen.spamhaus.org", []string{"127.255.255.254"}, []string{"Error: open resolver"})
	if listed {
		t.Errorf("expected 127.255.255.254 open-resolver error to be ignored")
	}

	// 3. URIBL query refused (127.0.0.1 with Query Refused TXT) must be ignored
	listed, _, _ = IsValidDNSBLListing("black.uribl.com", []string{"127.0.0.1"}, []string{"127.0.0.1 -> Query Refused"})
	if listed {
		t.Errorf("expected URIBL 127.0.0.1 query refused to be ignored")
	}

	// 4. Spamhaus PBL (127.0.0.10 / 127.0.0.11) dynamic ISP policy range should not be flagged as active abuse
	listed, _, _ = IsValidDNSBLListing("zen.spamhaus.org", []string{"127.0.0.10"}, nil)
	if listed {
		t.Errorf("expected Spamhaus PBL 127.0.0.10 to be ignored")
	}
}

func TestBuildExternalReputationLinks(t *testing.T) {
	domLinks := BuildExternalReputationLinks("example.com", false)
	if len(domLinks) == 0 {
		t.Fatalf("expected external reputation links for domain")
	}
	ipLinks := BuildExternalReputationLinks("93.184.216.34", true)
	if len(ipLinks) == 0 {
		t.Fatalf("expected external reputation links for IP")
	}
}

