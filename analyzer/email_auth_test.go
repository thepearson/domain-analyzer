package analyzer

import (
	"testing"
)

func TestParseDKIMRecord(t *testing.T) {
	// 1. Standard RSA DKIM record
	rawRSA := "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890"
	dkim, ok := ParseDKIMRecord("google", rawRSA, "")
	if !ok {
		t.Fatalf("expected valid DKIM record to parse")
	}
	if dkim.Selector != "google" || dkim.KeyType != "rsa" {
		t.Errorf("unexpected DKIM info: %+v", dkim)
	}

	// 2. Ed25519 DKIM record with CNAME
	rawEd := "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
	dkimEd, ok := ParseDKIMRecord("selector1", rawEd, "selector1-example-com._domainkey.example.onmicrosoft.com")
	if !ok {
		t.Fatalf("expected valid Ed25519 DKIM record to parse")
	}
	if dkimEd.KeyType != "ed25519" || dkimEd.CNAME == "" {
		t.Errorf("unexpected Ed25519 DKIM info: %+v", dkimEd)
	}

	// 3. Explicitly revoked DKIM key (empty p=) should return false
	revoked := "v=DKIM1; k=rsa; p="
	if _, ok := ParseDKIMRecord("default", revoked, ""); ok {
		t.Errorf("expected revoked DKIM record (empty p=) to return false")
	}
}

func TestParseMTASTS(t *testing.T) {
	dnsTxt := "v=STSv1; id=2026103001;"
	mtasts := ParseMTASTSDNS(dnsTxt)
	if !mtasts.Found || mtasts.ID != "2026103001" {
		t.Fatalf("unexpected MTA-STS DNS parse result: %+v", mtasts)
	}

	policyTxt := `version: STSv1
mode: enforce
mx: *.mail.protection.outlook.com
mx: aspmx.l.google.com
max_age: 604800
`
	ParseMTASTSPolicy(policyTxt, &mtasts)
	if mtasts.Mode != "enforce" || mtasts.MaxAge != "604800" {
		t.Errorf("unexpected MTA-STS policy mode/max_age: %+v", mtasts)
	}
	if len(mtasts.MXPatterns) != 2 {
		t.Errorf("expected 2 MX patterns, got %v", mtasts.MXPatterns)
	}
}

func TestParseTLSRPTAndBIMI(t *testing.T) {
	tlsrptTxt := "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://rpt.example.com/v1"
	rpt := ParseTLSRPT(tlsrptTxt)
	if !rpt.Found || len(rpt.Endpoints) != 2 {
		t.Fatalf("unexpected TLS-RPT parse result: %+v", rpt)
	}
	if rpt.Endpoints[0] != "mailto:tlsrpt@example.com" || rpt.Endpoints[1] != "https://rpt.example.com/v1" {
		t.Errorf("unexpected TLS-RPT endpoints: %v", rpt.Endpoints)
	}

	bimiTxt := "v=BIMI1; l=https://example.com/brand/logo.svg; a=https://example.com/brand/vmc.pem"
	bimi := ParseBIMI(bimiTxt)
	if !bimi.Found {
		t.Fatalf("expected BIMI record to be found")
	}
	if bimi.LogoURL != "https://example.com/brand/logo.svg" || bimi.AuthorityURL != "https://example.com/brand/vmc.pem" {
		t.Errorf("unexpected BIMI URLs: %+v", bimi)
	}
}
