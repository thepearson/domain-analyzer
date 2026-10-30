package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"domain-analyzer/analyzer"
	"domain-analyzer/storage"

	"github.com/egoist/mygo/ui"
)

func makeSamplePNG() []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.NRGBA{R: 30, G: 144, B: 255, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func TestWhoisBrowserURL(t *testing.T) {
	label, gotNZ := WhoisBrowserURL("www. spark.co.nz", "spark.co.nz")
	wantNZ := "https://dnc.org.nz/whois/whois-lookup/?domain_name=spark.co.nz"
	if gotNZ != wantNZ {
		t.Errorf("WhoisBrowserURL(.nz) = %q, want %q (label=%q)", gotNZ, wantNZ, label)
	}

	_, gotCom := WhoisBrowserURL("example.com", "example.com")
	if !strings.Contains(gotCom, "example.com") {
		t.Errorf("WhoisBrowserURL(.com) = %q, expected example.com", gotCom)
	}
}

func TestSortedSecurityHeadersDeterministic(t *testing.T) {
	headers := map[string]string{
		"X-Frame-Options":           "DENY",
		"Permissions-Policy":        "geolocation=()",
		"Strict-Transport-Security": "max-age=63072000",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "no-referrer",
		"X-Content-Type-Options":    "nosniff",
	}

	first := sortedSecurityHeaders(headers)
	for i := 0; i < 20; i++ {
		next := sortedSecurityHeaders(headers)
		for idx := range first {
			if first[idx] != next[idx] {
				t.Fatalf("header order changed at index %d: %+v vs %+v", idx, first, next)
			}
		}
	}
	if first[0].Key != "Strict-Transport-Security" {
		t.Errorf("expected first header to be Strict-Transport-Security, got %s", first[0].Key)
	}
}

func TestDesktopAppDrillDownAndFeatures(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gui_test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	defer store.Close()

	// Seed an initial .nz domain scan with favicon and security headers
	seedDomain := &analyzer.DomainInfo{
		Domain:     "portal.example.co.nz",
		ApexDomain: "example.co.nz",
		Registrar:  "Domain Name Commission",
		DNS: analyzer.DNSInfo{
			IPAddress: "93.184.216.34",
			IPOwner:   "Edgecast",
			IPTTL:     300,
		},
		Web: analyzer.WebInfo{
			Favicon:   makeSamplePNG(),
			TechStack: []string{"Cloudflare", "Nginx"},
			TechDetails: []analyzer.TechDetail{
				{
					Name:    "Cloudflare",
					Favicon: makeSamplePNG(),
				},
				{
					Name:    "Nginx",
					Version: "1.24.0",
					Favicon: makeSamplePNG(),
				},
			},
			SecurityHeaders: map[string]string{
				"Strict-Transport-Security": "max-age=31536000",
				"X-Frame-Options":           "SAMEORIGIN",
			},
		},
		WAF: analyzer.WAFInfo{
			Detected:    true,
			Summary:     "Cloudflare (Enforcing)",
			BaselineURL: "https://portal.example.co.nz",
			ProbeURL:    "https://portal.example.co.nz?probe_test=%3Cscript%3Ealert(1)%3C/script%3E",
		},
		TLS: analyzer.TLSInfo{
			HasTLS:     true,
			TLSIssuer:  "Let's Encrypt",
			SANDomains: []string{"*.example.co.nz", "api.example.co.nz"},
		},
	}

	parentID, err := store.SaveDomainScan(seedDomain, 0, "", false)
	if err != nil {
		t.Fatalf("SaveDomainScan failed: %v", err)
	}

	app := NewDesktopApp(store)
	doneCh := make(chan struct{}, 2)
	app.runner = ScanRunnerFunc{
		AnalyzeDomain: func(domain string, checkVulns bool) *analyzer.DomainInfo {
			defer func() { doneCh <- struct{}{} }()
			return &analyzer.DomainInfo{
				Domain:     domain,
				ApexDomain: "example.co.nz",
			}
		},
		AnalyzeIP: func(ip string, checkVulns bool) *analyzer.IPInfo {
			defer func() { doneCh <- struct{}{} }()
			return &analyzer.IPInfo{
				IP:         ip,
				Owner:      "Edgecast Networks",
				ASN:        "AS15133",
				PTRRecords: []string{"origin.example.co.nz"},
			}
		},
	}

	tester := ui.NewTester(app.View, 1280, 820)

	// Verify initial seeded scan, .nz WHOIS link, and OWASP challenge links are displayed
	if !tester.HasText("portal.example.co.nz") {
		t.Fatalf("expected UI to render seeded domain 'portal.example.co.nz'")
	}
	if !tester.HasText("Open Full .nz WHOIS (DNC) ↗") {
		t.Errorf("expected UI to render DNC .nz WHOIS link")
	}
	if !tester.HasText("OWASP XSS Challenge ↗") {
		t.Errorf("expected UI to render OWASP XSS Challenge link")
	}
	if !tester.HasText("Cloudflare ↗") {
		t.Errorf("expected UI to render clickable tech link 'Cloudflare ↗'")
	}
	if !tester.HasText("Nginx (1.24.0) ↗") {
		t.Errorf("expected UI to render clickable tech link 'Nginx (1.24.0) ↗'")
	}

	// Switch to Raw JSON tab and verify syntax-highlighted JSON & Copy button
	if err := tester.Click("Raw JSON"); err != nil {
		t.Fatalf("clicking 'Raw JSON' tab failed: %v", err)
	}
	if !tester.HasText("Copy JSON to Clipboard") {
		t.Fatalf("expected 'Copy JSON to Clipboard' button on Raw JSON tab")
	}
	if err := tester.Click("Copy JSON to Clipboard"); err != nil {
		t.Fatalf("clicking 'Copy JSON to Clipboard' failed: %v", err)
	}
	if !strings.Contains(tester.Clipboard(), `"domain": "portal.example.co.nz"`) {
		t.Errorf("expected formatted JSON in clipboard, got: %s", tester.Clipboard())
	}

	// Switch back to Overview & Details tab and drill down into IP
	if err := tester.Click("Overview & Details"); err != nil {
		t.Fatalf("clicking 'Overview & Details' tab failed: %v", err)
	}
	if err := tester.Click("Scan IP ↗"); err != nil {
		t.Fatalf("clicking 'Scan IP ↗' failed: %v", err)
	}

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background IP scan")
	}

	time.Sleep(50 * time.Millisecond)
	tester.Frame()

	if app.currentScan == nil || app.currentScan.Target != "93.184.216.34" {
		t.Fatalf("expected currentScan to navigate to drilled-down IP 93.184.216.34, got %+v", app.currentScan)
	}
	if app.currentScan.ParentScanID != parentID {
		t.Errorf("expected ParentScanID = %d, got %d", parentID, app.currentScan.ParentScanID)
	}

	// Verify favicon persisted across sessions in scan list
	app2 := NewDesktopApp(store)
	if len(app2.scans) != 2 {
		t.Fatalf("expected 2 persisted scans across sessions, got %d", len(app2.scans))
	}
	if len(app2.scans[1].Favicon) == 0 {
		t.Errorf("expected persisted favicon bytes on domain scan summary")
	}
}
