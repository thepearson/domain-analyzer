package analyzer

import (
	"testing"
)

func TestParseCrtShJSON(t *testing.T) {
	raw := []byte(`[
		{"common_name": "*.example.co.nz", "name_value": "*.example.co.nz\napi.example.co.nz\ndev.example.co.nz"},
		{"common_name": "portal.example.co.nz", "name_value": "portal.example.co.nz\nexample.co.nz\nunrelated.other.com"}
	]`)

	subs, err := ParseCrtShJSON(raw, "example.co.nz")
	if err != nil {
		t.Fatalf("ParseCrtShJSON failed: %v", err)
	}

	expected := []string{"api.example.co.nz", "dev.example.co.nz", "portal.example.co.nz"}
	if len(subs) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, subs)
	}
	for i := range expected {
		if subs[i] != expected[i] {
			t.Errorf("expected subs[%d] = %q, got %q", i, expected[i], subs[i])
		}
	}
}

func TestParseCertSpotterJSON(t *testing.T) {
	raw := []byte(`[
		{"dns_names": ["*.example.co.nz", "staging.example.co.nz", "auth.example.co.nz"]},
		{"dns_names": ["example.co.nz", "vpn.example.co.nz"]}
	]`)

	subs, err := ParseCertSpotterJSON(raw, "example.co.nz")
	if err != nil {
		t.Fatalf("ParseCertSpotterJSON failed: %v", err)
	}

	expected := []string{"auth.example.co.nz", "staging.example.co.nz", "vpn.example.co.nz"}
	if len(subs) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, subs)
	}
	for i := range expected {
		if subs[i] != expected[i] {
			t.Errorf("expected subs[%d] = %q, got %q", i, expected[i], subs[i])
		}
	}
}
