package main

import (
	"path/filepath"
	"testing"
	"time"

	"domain-analyzer/analyzer"
	"domain-analyzer/storage"

	"github.com/egoist/mygo/ui"
)

func TestDesktopAppDrillDownAndPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gui_test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	defer store.Close()

	// Seed an initial domain scan
	seedDomain := &analyzer.DomainInfo{
		Domain:     "portal.example.com",
		ApexDomain: "example.com",
		Registrar:  "Example Registrar",
		DNS: analyzer.DNSInfo{
			IPAddress: "93.184.216.34",
			IPOwner:   "Edgecast",
			IPTTL:     300,
		},
		TLS: analyzer.TLSInfo{
			HasTLS:     true,
			TLSIssuer:  "Let's Encrypt",
			SANDomains: []string{"*.example.com", "api.example.com"},
		},
	}

	parentID, err := store.SaveDomainScan(seedDomain, 0, "", false)
	if err != nil {
		t.Fatalf("SaveDomainScan failed: %v", err)
	}

	app := NewDesktopApp(store)
	// Mock scan runner for fast deterministic testing
	doneCh := make(chan struct{}, 2)
	app.runner = ScanRunnerFunc{
		AnalyzeDomain: func(domain string, checkVulns bool) *analyzer.DomainInfo {
			defer func() { doneCh <- struct{}{} }()
			return &analyzer.DomainInfo{
				Domain:     domain,
				ApexDomain: "example.com",
			}
		},
		AnalyzeIP: func(ip string, checkVulns bool) *analyzer.IPInfo {
			defer func() { doneCh <- struct{}{} }()
			return &analyzer.IPInfo{
				IP:         ip,
				Owner:      "Edgecast Networks",
				ASN:        "AS15133",
				PTRRecords: []string{"origin.example.com"},
			}
		},
	}

	tester := ui.NewTester(app.View, 1280, 820)

	// Verify initial seeded scan is displayed in the UI
	if !tester.HasText("portal.example.com") {
		t.Fatalf("expected UI to render seeded domain 'portal.example.com'")
	}
	if !tester.HasText("93.184.216.34") {
		t.Fatalf("expected UI to render discovered IP '93.184.216.34'")
	}
	if !tester.HasText("api.example.com") {
		t.Fatalf("expected UI to render discovered TLS SAN 'api.example.com'")
	}

	// Drill down into discovered IP 93.184.216.34 via 'Scan IP ↗' button
	if err := tester.Click("Scan IP ↗"); err != nil {
		t.Fatalf("clicking 'Scan IP ↗' failed: %v", err)
	}

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background IP scan")
	}

	// Wait briefly for runOnUI completion and render next frame
	time.Sleep(50 * time.Millisecond)
	tester.Frame()

	if app.currentScan == nil || app.currentScan.Target != "93.184.216.34" {
		t.Fatalf("expected currentScan to navigate to drilled-down IP 93.184.216.34, got %+v", app.currentScan)
	}
	if app.currentScan.ParentScanID != parentID {
		t.Errorf("expected ParentScanID = %d, got %d", parentID, app.currentScan.ParentScanID)
	}
	if !tester.HasText("← Parent Scan") {
		t.Errorf("expected '← Parent Scan' button to be visible on child scan")
	}
	if !tester.HasText("origin.example.com") {
		t.Errorf("expected PTR record 'origin.example.com' to be visible on IP scan")
	}

	// Verify persistence across sessions by opening a fresh DesktopApp on the same SQLite DB
	app2 := NewDesktopApp(store)
	if len(app2.scans) != 2 {
		t.Fatalf("expected 2 persisted scans across sessions, got %d", len(app2.scans))
	}
}

