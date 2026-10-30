package analyzer

import (
	"testing"
)

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"8.8.8.8", true},
		{"https://93.184.216.34:443/test", true},
		{"2001:4860:4860::8888", true},
		{"example.com", false},
		{"sub.example.co.uk", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := IsIPAddress(tc.input); got != tc.want {
			t.Errorf("IsIPAddress(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseIPWhoisDetails(t *testing.T) {
	sample := `
# ARIN WHOIS data
NetRange:       104.16.0.0 - 104.31.255.255
CIDR:           104.16.0.0/12
NetName:        CLOUDFLARENET
OrgName:        Cloudflare, Inc.
OriginAS:       AS13335
Country:        US
`
	owner, asn, cidr, country := ParseIPWhoisDetails(sample)
	if owner != "Cloudflare, Inc." {
		t.Errorf("owner = %q, want %q", owner, "Cloudflare, Inc.")
	}
	if asn != "AS13335" {
		t.Errorf("asn = %q, want %q", asn, "AS13335")
	}
	if cidr != "104.16.0.0/12" {
		t.Errorf("cidr = %q, want %q", cidr, "104.16.0.0/12")
	}
	if country != "US" {
		t.Errorf("country = %q, want %q", country, "US")
	}
}

func TestExtractDomainPivots(t *testing.T) {
	info := &DomainInfo{
		Domain:     "app.example.com",
		ApexDomain: "example.com",
		DNS: DNSInfo{
			IPAddress:   "93.184.216.34",
			WWWAddress:  "93.184.216.35",
			Nameservers: []string{"ns1.cloudflare.com.", "ns2.cloudflare.com."},
		},
		WAF: WAFInfo{
			CNAMEs: []string{"app.example.com.cdn.cloudflare.net"},
		},
		TLS: TLSInfo{
			SANDomains: []string{"*.example.com", "app.example.com", "api.example.com"},
		},
		Email: EmailInfo{
			SPFRecord: &SPFDetails{
				Includes: []string{"_spf.google.com"},
			},
		},
	}

	pivots := ExtractDomainPivots(info)
	found := make(map[string]PivotTarget)
	for _, p := range pivots {
		found[string(p.Type)+":"+p.Target] = p
	}

	// Self domain ("app.example.com") should be excluded
	if _, ok := found["domain:app.example.com"]; ok {
		t.Errorf("expected self domain app.example.com to be excluded from pivots")
	}

	expected := []struct {
		key    string
		reason string
	}{
		{"domain:example.com", "Apex Domain"},
		{"ip:93.184.216.34", "A Record"},
		{"ip:93.184.216.35", "WWW Record"},
		{"domain:app.example.com.cdn.cloudflare.net", "CNAME"},
		{"domain:api.example.com", "TLS SAN"},
		{"domain:_spf.google.com", "SPF Include"},
		{"domain:ns1.cloudflare.com", "Nameserver"},
	}

	for _, exp := range expected {
		p, ok := found[exp.key]
		if !ok {
			t.Errorf("missing expected pivot %s", exp.key)
			continue
		}
		if p.Reason != exp.reason {
			t.Errorf("pivot %s reason = %q, want %q", exp.key, p.Reason, exp.reason)
		}
	}
}

func TestExtractIPPivots(t *testing.T) {
	info := &IPInfo{
		IP:         "8.8.8.8",
		PTRRecords: []string{"dns.google."},
		TLS: TLSInfo{
			SANDomains: []string{"*.dns.google.com", "dns.google"},
		},
	}

	pivots := ExtractIPPivots(info)
	if len(pivots) != 2 {
		t.Fatalf("expected 2 unique domain pivots, got %d: %+v", len(pivots), pivots)
	}
	if pivots[0].Target != "dns.google" || pivots[0].Reason != "PTR Record" {
		t.Errorf("unexpected first pivot: %+v", pivots[0])
	}
	if pivots[1].Target != "dns.google.com" || pivots[1].Reason != "TLS SAN" {
		t.Errorf("unexpected second pivot: %+v", pivots[1])
	}
}
