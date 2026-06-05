package analyzer

import (
	"reflect"
	"sort"
	"testing"
)

func TestIdentifyMailProviders(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		expected []string
	}{
		{
			name:     "Google Workspace",
			hosts:    []string{"aspmx.l.google.com.", "alt1.aspmx.l.google.com."},
			expected: []string{"Google Workspace"},
		},
		{
			name:     "Microsoft Outlook",
			hosts:    []string{"microsoft-com.mail.protection.outlook.com."},
			expected: []string{"Microsoft Outlook/Office 365"},
		},
		{
			name:     "Proton Mail",
			hosts:    []string{"mail.protonmail.ch.", "mailsec.protonmail.ch."},
			expected: []string{"Proton Mail"},
		},
		{
			name:     "Multiple Providers",
			hosts:    []string{"aspmx.l.google.com.", "mx.zoho.com."},
			expected: []string{"Google Workspace", "Zoho Mail"},
		},
		{
			name:     "Generic Provider",
			hosts:    []string{"mx1.example.com."},
			expected: []string{"Generic/Other (MX records found)"},
		},
		{
			name:     "No MX Records",
			hosts:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IdentifyMailProviders(tt.hosts)
			sort.Strings(got)
			sort.Strings(tt.expected)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("IdentifyMailProviders() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseIPOwner(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ARIN Format",
			input:    "OrgName:        Google LLC\nOrgID:          GOGL",
			expected: "Google LLC",
		},
		{
			name:     "RIPE Format",
			input:    "descr:          Google Ireland Limited\ncountry:        IE",
			expected: "Google Ireland Limited",
		},
		{
			name:     "APNIC Format",
			input:    "owner:          Google Asia Pacific\naddress:        Singapore",
			expected: "Google Asia Pacific",
		},
		{
			name:     "Organization Field",
			input:    "organization:   Some Hosting Co.",
			expected: "Some Hosting Co.",
		},
		{
			name:     "No match",
			input:    "Something:      Else",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseIPOwner(tt.input)
			if got != tt.expected {
				t.Errorf("ParseIPOwner() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseSPF(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *SPFDetails
	}{
		{
			name:  "Basic SPF with softfail",
			input: "v=spf1 include:_spf.google.com ~all",
			expected: &SPFDetails{
				Raw:      "v=spf1 include:_spf.google.com ~all",
				Policy:   "Soft Fail (~all)",
				Includes: []string{"_spf.google.com"},
			},
		},
		{
			name:  "SPF with multiple includes and fail",
			input: "v=spf1 include:spf.example.com include:other.com -all",
			expected: &SPFDetails{
				Raw:      "v=spf1 include:spf.example.com include:other.com -all",
				Policy:   "Fail (-all)",
				Includes: []string{"spf.example.com", "other.com"},
			},
		},
		{
			name:  "SPF with neutral",
			input: "v=spf1 ?all",
			expected: &SPFDetails{
				Raw:    "v=spf1 ?all",
				Policy: "Neutral (?all)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSPF(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseSPF() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *DMARCDetails
	}{
		{
			name:  "Basic DMARC with reject",
			input: "v=DMARC1; p=reject; rua=mailto:reports@example.com",
			expected: &DMARCDetails{
				Raw:              "v=DMARC1; p=reject; rua=mailto:reports@example.com",
				Policy:           "reject",
				AggregateReports: []string{"mailto:reports@example.com"},
			},
		},
		{
			name:  "DMARC with multiple reports and quarantine",
			input: "v=DMARC1; p=quarantine; rua=mailto:a@test.com, mailto:b@test.com",
			expected: &DMARCDetails{
				Raw:              "v=DMARC1; p=quarantine; rua=mailto:a@test.com, mailto:b@test.com",
				Policy:           "quarantine",
				AggregateReports: []string{"mailto:a@test.com", "mailto:b@test.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDMARC(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseDMARC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIdentifyNSProviders(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		expected []string
	}{
		{
			name:     "Cloudflare NS",
			hosts:    []string{"charles.ns.cloudflare.com.", "vera.ns.cloudflare.com."},
			expected: []string{"Cloudflare"},
		},
		{
			name:     "Route 53 NS",
			hosts:    []string{"ns-2048.awsdns-64.com.", "ns-0.awsdns-00.com."},
			expected: []string{"AWS Route 53"},
		},
		{
			name:     "Multiple NS Providers",
			hosts:    []string{"ns1.cloudflare.com.", "ns1.digitalocean.com."},
			expected: []string{"Cloudflare", "DigitalOcean"},
		},
		{
			name:     "Unknown Provider",
			hosts:    []string{"ns1.customdomain.com."},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IdentifyNSProviders(tt.hosts)
			sort.Strings(got)
			sort.Strings(tt.expected)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("IdentifyNSProviders() = %v, want %v", got, tt.expected)
			}
		})
	}
}
