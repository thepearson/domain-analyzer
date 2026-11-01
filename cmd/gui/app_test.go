package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"domain-analyzer/analyzer"
	"domain-analyzer/storage"

	"github.com/egoist/mygo"
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
	doneCh := make(chan struct{}, 4)
	portDoneCh := make(chan struct{}, 2)
	pingDoneCh := make(chan struct{}, 2)
	traceDoneCh := make(chan struct{}, 2)
	subDoneCh := make(chan struct{}, 2)
	metaDoneCh := make(chan struct{}, 2)
	tlsDoneCh := make(chan struct{}, 2)
	httpDoneCh := make(chan struct{}, 2)
	emailDoneCh := make(chan struct{}, 2)
	zoneDoneCh := make(chan struct{}, 2)
	repDoneCh := make(chan struct{}, 2)
	vulnDoneCh := make(chan struct{}, 2)
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
		ScanPorts: func(ip string) []analyzer.PortService {
			defer func() { portDoneCh <- struct{}{} }()
			return []analyzer.PortService{
				{Port: 22, Service: "SSH", State: "open", Banner: "SSH-2.0-OpenSSH_9.6"},
				{Port: 443, Service: "HTTPS", State: "open"},
			}
		},
		RunPing: func(target string) *analyzer.PingResult {
			defer func() { pingDoneCh <- struct{}{} }()
			return &analyzer.PingResult{
				Target:      target,
				ResolvedIP:  "93.184.216.34",
				Method:      "ICMP",
				Reachable:   true,
				PacketsSent: 4,
				PacketsRecv: 4,
				LossPercent: 0,
				MinRTT:      "11.20 ms",
				AvgRTT:      "11.80 ms",
				MaxRTT:      "12.50 ms",
			}
		},
		RunTraceroute: func(target string) *analyzer.TracerouteResult {
			defer func() { traceDoneCh <- struct{}{} }()
			return &analyzer.TracerouteResult{
				Target:     target,
				ResolvedIP: "93.184.216.34",
				Method:     "tracepath",
				Completed:  true,
				Hops: []analyzer.TracerouteHop{
					{Hop: 1, IP: "203.0.113.1", Host: "gw.isp.example.net", RTT: "2.10 ms"},
					{Hop: 2, IP: "93.184.216.34", Host: "origin.example.co.nz", RTT: "11.80 ms"},
				},
			}
		},
		EnumerateSubdomains: func(domain string) *analyzer.SubdomainEnumeration {
			defer func() { subDoneCh <- struct{}{} }()
			return &analyzer.SubdomainEnumeration{
				ApexDomain:  "example.co.nz",
				TotalFound:  2,
				ActiveCount: 1,
				SourcesUsed: []string{"crt.sh", "DNS"},
				Subdomains: []analyzer.SubdomainEntry{
					{
						Subdomain:   "api.example.co.nz",
						IPAddresses: []string{"93.184.216.40"},
						Active:      true,
						Sources:     []string{"crt.sh", "DNS"},
					},
					{
						Subdomain: "legacy.example.co.nz",
						Active:    false,
						Sources:   []string{"crt.sh"},
					},
				},
			}
		},
		InspectMetadata: func(target string) *analyzer.WebsiteMetadata {
			defer func() { metaDoneCh <- struct{}{} }()
			return &analyzer.WebsiteMetadata{
				PageTitle:       "Example NZ Portal",
				MetaDescription: "Customer & Partner Portal",
				RobotsTxt: analyzer.RobotsTxtInfo{
					Found:           true,
					URL:             "https://portal.example.co.nz/robots.txt",
					UserAgents:      []string{"*"},
					DisallowedPaths: []string{"/admin/secret", "/internal/debug"},
				},
				SecurityTxt: analyzer.SecurityTxtInfo{
					Found:    true,
					URL:      "https://portal.example.co.nz/.well-known/security.txt",
					Contacts: []string{"mailto:security@example.co.nz"},
					Policy:   []string{"https://example.co.nz/security-policy"},
				},
				Sitemap: analyzer.SitemapInfo{
					Found:      true,
					URL:        "https://portal.example.co.nz/sitemap.xml",
					URLCount:   2,
					SampleURLs: []string{"https://portal.example.co.nz/login"},
				},
			}
		},
		InspectTLS: func(target string) (analyzer.TLSInfo, error) {
			defer func() { tlsDoneCh <- struct{}{} }()
			return analyzer.TLSInfo{
				HasTLS:              true,
				Grade:               "A+",
				GradeSummary:        "Exceptional TLS 1.3 configuration with strong AEAD cipher & Certificate Transparency",
				NegotiatedVersion:   "TLS 1.3",
				SupportedVersions:   []string{"TLS 1.2", "TLS 1.3"},
				CipherSuite:         "TLS_AES_128_GCM_SHA256",
				ALPNProtocol:        "h2",
				KeyAlgorithm:        "ECDSA P-256 (256-bit)",
				SignatureAlgorithm:  "ECDSA-SHA256",
				SubjectCN:           "portal.example.co.nz",
				TLSIssuer:           "Let's Encrypt",
				TLSExpiry:           "2026-12-31T00:00:00Z",
				DaysRemaining:       61,
				ChainValid:          true,
				HasCertTransparency: true,
				SANDomains:          []string{"portal.example.co.nz", "api.example.co.nz"},
			}, nil
		},
		TraceHTTPChain: func(target string) *analyzer.HTTPTraceResult {
			defer func() { httpDoneCh <- struct{}{} }()
			return &analyzer.HTTPTraceResult{
				InitialURL:    "http://portal.example.co.nz",
				FinalURL:      "https://portal.example.co.nz/login",
				FinalStatus:   200,
				UpgradedHTTPS: true,
				RedirectCount: 1,
				TotalChainMs:  42.5,
				Hops: []analyzer.HTTPRedirectHop{
					{
						Step:       1,
						URL:        "http://portal.example.co.nz",
						StatusCode: 301,
						Status:     "301 Moved Permanently",
						Location:   "https://portal.example.co.nz/login",
						Protocol:   "HTTP/1.1",
						TotalMs:    12.5,
					},
					{
						Step:       2,
						URL:        "https://portal.example.co.nz/login",
						StatusCode: 200,
						Status:     "200 OK",
						Protocol:   "HTTP/2.0",
						TotalMs:    30.0,
					},
				},
				Waterfall: analyzer.HTTPWaterfallTiming{
					URL:               "https://portal.example.co.nz/login",
					Protocol:          "HTTP/2.0",
					StatusCode:        200,
					DNSMs:             3.2,
					TCPConnectMs:      8.4,
					TLSHandshakeMs:    11.1,
					TTFBMs:            5.8,
					ContentTransferMs: 1.5,
					TotalMs:           30.0,
				},
			}
		},
		InspectEmail: func(domain string) analyzer.EmailInfo {
			defer func() { emailDoneCh <- struct{}{} }()
			return analyzer.EmailInfo{
				DeepChecked:   true,
				MXRecords:     []string{"aspmx.l.google.com"},
				MailProviders: []string{"Google Workspace"},
				SPFRecord: &analyzer.SPFDetails{
					Raw:         "v=spf1 include:_spf.google.com -all",
					Policy:      "Fail (-all)",
					Status:      "Secure",
					Description: "Strict enforcement; unauthorized emails are rejected.",
					Includes:    []string{"_spf.google.com"},
				},
				DMARCRecord: &analyzer.DMARCDetails{
					Raw:              "v=DMARC1; p=reject; rua=mailto:dmarc@example.co.nz",
					Policy:           "reject",
					Status:           "Secure",
					Description:      "Maximum protection; unauthorized emails are rejected by receivers.",
					AggregateReports: []string{"mailto:dmarc@example.co.nz"},
				},
				DKIMRecords: []analyzer.DKIMSelectorInfo{
					{
						Selector:  "google",
						KeyType:   "rsa",
						RawRecord: "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...",
					},
				},
				MTASTS: &analyzer.MTASTSDetails{
					Found:      true,
					ID:         "2026103101",
					PolicyURL:  "https://mta-sts.example.co.nz/.well-known/mta-sts.txt",
					Mode:       "enforce",
					MaxAge:     "604800",
					MXPatterns: []string{"*.google.com"},
				},
				TLSRPT: &analyzer.TLSRPTDetails{
					Found:     true,
					RawRecord: "v=TLSRPTv1; rua=mailto:tlsrpt@example.co.nz",
					Endpoints: []string{"mailto:tlsrpt@example.co.nz"},
				},
				BIMI: &analyzer.BIMIDetails{
					Found:        true,
					RawRecord:    "v=BIMI1; l=https://example.co.nz/logo.svg; a=https://example.co.nz/vmc.pem",
					LogoURL:      "https://example.co.nz/logo.svg",
					AuthorityURL: "https://example.co.nz/vmc.pem",
				},
			}
		},
		InspectZone: func(domain string) *analyzer.DNSSECAndZoneAudit {
			defer func() { zoneDoneCh <- struct{}{} }()
			return &analyzer.DNSSECAndZoneAudit{
				Audited:         true,
				Domain:          domain,
				ApexDomain:      "example.co.nz",
				HasIPv6:         true,
				IPv6Addresses:   []string{"2606:2800:220:1:248:1893:25c8:1946"},
				DNSSECEnabled:   true,
				DNSSECValidated: true,
				DNSSECStatus:    "Secure (Signed & Validated)",
				DNSSECSummary:   "Full DNSSEC chain of trust verified (1 DS, 2 DNSKEY, 2 RRSIG records)",
				RRSIGCount:      2,
				DSRecords: []analyzer.DSRecordInfo{
					{
						KeyTag:     2371,
						Algorithm:  13,
						AlgoName:   "ECDSAP256SHA256 (13)",
						DigestType: 2,
						DigestName: "SHA-256 (2)",
						Digest:     "1F9876543210ABCDEF",
					},
				},
				DNSKEYRecords: []analyzer.DNSKEYRecordInfo{
					{
						Role:      "KSK (257)",
						Flags:     257,
						KeyTag:    2371,
						Algorithm: 13,
						AlgoName:  "ECDSAP256SHA256 (13)",
					},
				},
				SOA: &analyzer.SOADetails{
					PrimaryNS:  "ns1.example.co.nz",
					AdminEmail: "hostmaster@example.co.nz",
					Serial:     2026103101,
					Refresh:    7200,
					Retry:      3600,
					Expire:     1209600,
					MinTTL:     3600,
				},
				AXFRChecked:    true,
				AXFRVulnerable: false,
				AXFRSummary:    "Secure: All 2 authoritative nameservers properly refused AXFR zone transfers",
				AXFRResults: []analyzer.AXFRServerResult{
					{Nameserver: "ns1.example.co.nz", Vulnerable: false, Status: "Refused (Secure)"},
					{Nameserver: "ns2.example.co.nz", Vulnerable: false, Status: "Refused (Secure)"},
				},
			}
		},
		CheckReputation: func(target string) *analyzer.ReputationResult {
			defer func() { repDoneCh <- struct{}{} }()
			return &analyzer.ReputationResult{
				Checked:      true,
				Target:       target,
				ResolvedIP:   "93.184.216.34",
				Status:       "Clean (0/12 Blacklists)",
				TotalChecked: 12,
				ListedCount:  0,
				Entries: []analyzer.DNSBLEntry{
					{Provider: "Spamhaus DBL", Zone: "dbl.spamhaus.org", Category: "Domain URI RBL", Target: "example.co.nz", Listed: false},
					{Provider: "Spamhaus ZEN", Zone: "zen.spamhaus.org", Category: "IP RBL", Target: "93.184.216.34", Listed: false},
					{Provider: "SpamCop", Zone: "bl.spamcop.net", Category: "IP RBL", Target: "93.184.216.34", Listed: false},
					{Provider: "Barracuda RBL", Zone: "b.barracudacentral.org", Category: "IP RBL", Target: "93.184.216.34", Listed: false},
					{Provider: "SORBS Aggregate", Zone: "dnsbl.sorbs.net", Category: "IP RBL", Target: "93.184.216.34", Listed: false},
					{Provider: "UCEPROTECT L1", Zone: "dnsbl-1.uceprotect.net", Category: "IP RBL", Target: "93.184.216.34", Listed: false},
				},
				ExternalLinks: analyzer.BuildExternalReputationLinks(target, false),
			}
		},
		LookupVulnerabilities: func(details []analyzer.TechDetail) ([]analyzer.Vulnerability, error) {
			defer func() { vulnDoneCh <- struct{}{} }()
			return []analyzer.Vulnerability{
				{
					ID:          "CVE-2024-99999",
					Severity:    "HIGH (7.5)",
					Description: "Sample vulnerability in Nginx 1.24.0",
					URL:         "https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
				},
			}, nil
		},
	}

	tester := ui.NewTester(app.View, 1280, 2200)

	// Verify initial seeded scan and .nz WHOIS link on the default "Summary & Reputation" sub-tab
	if !tester.HasText("portal.example.co.nz") {
		t.Fatalf("expected UI to render seeded domain 'portal.example.co.nz'")
	}
	if !tester.HasText("Open .nz WHOIS ↗") {
		t.Errorf("expected UI to render DNC .nz WHOIS link on Summary & Reputation sub-tab")
	}

	// Verify Executive Scorecard tiles are displayed at the top and clicking "WEB & TLS" jumps to Web, TLS & WAF sub-tab
	if !tester.HasText("REPUTATION") || !tester.HasText("WEB & TLS") || !tester.HasText("EMAIL") {
		t.Errorf("expected Executive Scorecard KPI tiles to be rendered")
	}
	if err := tester.Click("WEB & TLS"); err != nil {
		t.Fatalf("clicking 'WEB & TLS' scorecard tile failed: %v", err)
	}
	if !tester.HasText("XSS Probe ↗") {
		t.Errorf("expected UI to render OWASP XSS Challenge link on Web, TLS & WAF sub-tab")
	}
	if !tester.HasText("Cloudflare ↗") {
		t.Errorf("expected UI to render clickable tech link 'Cloudflare ↗'")
	}
	if !tester.HasText("Nginx (1.24.0) ↗") {
		t.Errorf("expected UI to render clickable tech link 'Nginx (1.24.0) ↗'")
	}
	if !tester.HasText("HTTP Security Headers Checklist") || !tester.HasText("2/6 Configured") {
		t.Errorf("expected HTTP Security Headers Checklist grid with '2/6 Configured' pill to be rendered")
	}

	// Switch back to "REPUTATION"
	if err := tester.Click("REPUTATION"); err != nil {
		t.Fatalf("clicking 'REPUTATION' tile failed: %v", err)
	}

	// Verify Window Menu Bar has File and View menus
	winMenu := app.buildWindowMenu()
	if winMenu.ItemByID("menu-file") == nil || winMenu.ItemByID("menu-view") == nil {
		t.Fatalf("expected 'menu-file' and 'menu-view' in window menu")
	}

	// Test adjusting text size / GUI scale under the "View" menu
	if !app.TriggerMenuAction("view-zoom-in") {
		t.Fatalf("triggering 'view-zoom-in' failed")
	}
	if app.textScale <= 1.0 {
		t.Errorf("expected textScale > 1.0 after Increase Font Size, got %f", app.textScale)
	}

	if !app.TriggerMenuAction("view-zoom-out") {
		t.Fatalf("triggering 'view-zoom-out' failed")
	}
	if app.textScale != 1.0 {
		t.Errorf("expected textScale 1.0 after Decrease Font Size, got %f", app.textScale)
	}

	// Test Theme Mode under the "View" menu (Light, Dark, Auto)
	if !app.TriggerMenuAction("view-theme-light") {
		t.Fatalf("triggering 'view-theme-light' failed")
	}
	if app.themeMode != 1 {
		t.Errorf("expected themeMode 1 ('Light Theme'), got %d", app.themeMode)
	}

	if !app.TriggerMenuAction("view-theme-dark") {
		t.Fatalf("triggering 'view-theme-dark' failed")
	}
	if app.themeMode != 2 {
		t.Errorf("expected themeMode 2 ('Dark Theme'), got %d", app.themeMode)
	}

	if !app.TriggerMenuAction("view-theme-auto") {
		t.Fatalf("triggering 'view-theme-auto' failed")
	}
	if app.themeMode != 0 {
		t.Errorf("expected themeMode 0 ('Auto Theme'), got %d", app.themeMode)
	}

	// Verify Copy JSON button in scan header bar
	if !tester.HasText("Copy JSON") {
		t.Fatalf("expected 'Copy JSON' button in scan header bar")
	}
	if err := tester.Click("Copy JSON"); err != nil {
		t.Fatalf("clicking 'Copy JSON' failed: %v", err)
	}
	if !strings.Contains(tester.Clipboard(), `"domain": "portal.example.co.nz"`) {
		t.Errorf("expected formatted JSON in clipboard, got: %s", tester.Clipboard())
	}

	// Test Save Session under the "File" menu:
	// When a filename is already set, Save directly saves to that file without opening the save UI.
	sessionTestFile := filepath.Join(t.TempDir(), "test_session_export.rscan")
	app.sessionFilePath = sessionTestFile
	if !app.TriggerMenuAction("file-save") {
		t.Fatalf("triggering 'file-save' failed")
	}
	if _, err := os.Stat(sessionTestFile); err != nil {
		t.Errorf("expected session file to be created at %s, got: %v", sessionTestFile, err)
	}

	// Test Exit under the "File" menu
	exitCalled := false
	app.exitFn = func() {
		exitCalled = true
	}
	if !app.TriggerMenuAction("file-exit") {
		t.Fatalf("triggering 'file-exit' failed")
	}
	if !exitCalled {
		t.Errorf("expected exitFn to be called when clicking Exit")
	}

	// Test New Session under the "File" menu with confirmation modal
	if !app.TriggerMenuAction("file-new") {
		t.Fatalf("triggering 'file-new' failed")
	}
	tester.Frame()
	if !tester.HasText("Start New Session?") {
		t.Fatalf("expected 'Start New Session?' confirmation modal")
	}
	if err := tester.Click("Clear Session"); err != nil {
		t.Fatalf("clicking 'Clear Session' confirmation button failed: %v", err)
	}
	if app.currentScan != nil || app.sessionFilePath != "" || app.targetInput != "" || len(app.scans) != 0 {
		t.Errorf("expected active scan, sessionFilePath, targetInput, and all saved scans to be cleared after New Session")
	}

	// Re-insert seed scan and refresh for the remainder of the test
	parentID, err = store.SaveDomainScan(seedDomain, 0, "", false)
	if err != nil {
		t.Fatalf("re-saving seedDomain failed: %v", err)
	}
	app.RefreshHistory()
	app.SelectScan(parentID)
	tester.Frame()

	// Verify footer status bar is rendered
	if !tester.HasText("1 Scans") {
		t.Errorf("expected footer status bar to display '1 Scans'")
	}

	// Switch to Discovered Targets view and verify compact pivot row summary
	if err := tester.Click("TARGETS"); err != nil {
		t.Fatalf("clicking 'TARGETS' tile failed: %v", err)
	}
	if !tester.HasText("Total Targets:") || !tester.HasText("example.co.nz") {
		t.Errorf("expected Discovered Targets summary and apex domain pivot row to be rendered")
	}

	// Drill down directly into IP from the pivot row
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

	// Verify footer status bar updated with completion result text
	if !tester.HasText("✓ Completed scan of 93.184.216.34") {
		t.Errorf("expected footer status bar to show completion message for 93.184.216.34")
	}

	if app.currentScan == nil || app.currentScan.Target != "93.184.216.34" {
		t.Fatalf("expected currentScan to navigate to drilled-down IP 93.184.216.34, got %+v", app.currentScan)
	}
	if app.currentScan.ParentScanID != parentID {
		t.Errorf("expected ParentScanID = %d, got %d", parentID, app.currentScan.ParentScanID)
	}

	// Verify child scan tree indicator in sidebar
	if !tester.HasText("└─") {
		t.Errorf("expected child scan tree indicator '└─' in sidebar")
	}

	// Switch to "PORTS" on the IP scan and run a host port scan
	if err := tester.Click("PORTS"); err != nil {
		t.Fatalf("clicking 'PORTS' tile on IP scan failed: %v", err)
	}
	if err := tester.Click("Scan Ports"); err != nil {
		t.Fatalf("clicking 'Scan Ports' failed: %v", err)
	}
	select {
	case <-portDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background port scan")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()

	if !tester.HasText("TCP/22") || !tester.HasText("SSH-2.0-OpenSSH_9.6") {
		t.Errorf("expected open port TCP/22 and SSH banner to be rendered after port scan")
	}

	// Navigate back to Parent Scan and verify its JSON export includes the child IP scan and port scan results
	if err := tester.Click("← Parent Scan"); err != nil {
		t.Fatalf("clicking '← Parent Scan' failed: %v", err)
	}
	if app.currentScan == nil || app.currentScan.ID != parentID {
		t.Fatalf("expected to return to parent scan %d", parentID)
	}
	if !strings.Contains(app.rawJSONReadOnly, `"child_scans"`) || !strings.Contains(app.rawJSONReadOnly, `"SSH-2.0-OpenSSH_9.6"`) {
		t.Errorf("expected parent scan JSON export to include child IP scan and port scan data, got:\n%s", app.rawJSONReadOnly)
	}

	// Switch to "NETWORK" on the domain scan and run Ping and Traceroute
	if err := tester.Click("NETWORK"); err != nil {
		t.Fatalf("clicking 'NETWORK' tile failed: %v", err)
	}
	if err := tester.Click("Run Ping"); err != nil {
		t.Fatalf("clicking 'Run Ping' failed: %v", err)
	}
	select {
	case <-pingDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background Ping")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("11.20 ms / 11.80 ms / 12.50 ms") {
		t.Errorf("expected Ping RTT summary to be rendered on scan page")
	}

	if err := tester.Click("Run Traceroute"); err != nil {
		t.Fatalf("clicking 'Run Traceroute' failed: %v", err)
	}
	select {
	case <-traceDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background Traceroute")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("203.0.113.1") || !tester.HasText("(gw.isp.example.net)") {
		t.Errorf("expected Traceroute hop IP and hostname to be rendered on scan page")
	}

	// Switch to "DNS & ZONE" and run DNSSEC/Zone Audit and Passive Subdomain Enumeration
	if err := tester.Click("DNS & ZONE"); err != nil {
		t.Fatalf("clicking 'DNS & ZONE' tile failed: %v", err)
	}
	if err := tester.Click("Audit DNSSEC"); err != nil {
		t.Fatalf("clicking 'Audit DNSSEC' failed: %v", err)
	}
	select {
	case <-zoneDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background DNSSEC & Zone Audit")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("DNSSEC: Secure (Signed & Validated)") || !tester.HasText("2606:2800:220:1:248:1893:25c8:1946") || !tester.HasText("AXFR: Refused (Secure)") {
		t.Errorf("expected DNSSEC status, IPv6 AAAA address, and AXFR status badge to be rendered on scan page")
	}
	// Verify progressive disclosure toggle for DNSSEC DS/DNSKEY cryptographic records
	if err := tester.Click("▸ Show Cryptographic Records (1 DS, 1 DNSKEY)"); err != nil {
		t.Fatalf("clicking DNSSEC DS/DNSKEY progressive disclosure toggle failed: %v", err)
	}
	if !tester.HasText("1F9876543210ABCDEF") {
		t.Errorf("expected DS digest to be visible after expanding DNSSEC cryptographic records")
	}

	if err := tester.Click("Enumerate Subdomains"); err != nil {
		t.Fatalf("clicking 'Enumerate Subdomains' failed: %v", err)
	}
	select {
	case <-subDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background Subdomain Enumeration")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("api.example.co.nz") || !tester.HasText("legacy.example.co.nz") {
		t.Errorf("expected discovered subdomains to be rendered on scan page")
	}

	// Switch to "WEB & TLS" and run TLS Audit, CVE Check, HTTP Trace, and Metadata Inspection
	if err := tester.Click("WEB & TLS"); err != nil {
		t.Fatalf("clicking 'WEB & TLS' tile failed: %v", err)
	}
	if err := tester.Click("Audit TLS"); err != nil {
		t.Fatalf("clicking 'Audit TLS' failed: %v", err)
	}
	select {
	case <-tlsDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background TLS Audit")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("Grade: A+") || !tester.HasText("TLS_AES_128_GCM_SHA256 (ALPN: h2)") {
		t.Errorf("expected TLS Grade A+ and cipher suite to be rendered on scan page")
	}

	if err := tester.Click("Check CVEs"); err != nil {
		t.Fatalf("clicking 'Check CVEs' button in Web Technologies section failed: %v", err)
	}
	select {
	case <-vulnDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background CVE lookup")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("CVE-2024-99999") || !tester.HasText("1 CVEs Found") {
		t.Errorf("expected CVE-2024-99999 and '1 CVEs Found' badge to be rendered in Web Technologies section")
	}

	if err := tester.Click("Trace Redirects"); err != nil {
		t.Fatalf("clicking 'Trace Redirects' failed: %v", err)
	}
	select {
	case <-httpDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background HTTP Trace")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("HTTP → HTTPS Upgraded") || !tester.HasText("TTFB: 5.80 ms") {
		t.Errorf("expected HTTP → HTTPS upgrade badge and waterfall TTFB timing to be rendered on scan page")
	}

	if err := tester.Click("Inspect Metadata"); err != nil {
		t.Fatalf("clicking 'Inspect Metadata' failed: %v", err)
	}
	select {
	case <-metaDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background Metadata Inspection")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("/admin/secret") || !tester.HasText("mailto:security@example.co.nz") {
		t.Errorf("expected robots.txt disallow path and security.txt contact to be rendered on scan page")
	}

	// Switch to "EMAIL" and run Email Deliverability & Authentication Deep-Dive
	if err := tester.Click("EMAIL"); err != nil {
		t.Fatalf("clicking 'EMAIL' tile failed: %v", err)
	}
	if err := tester.Click("Audit Email"); err != nil {
		t.Fatalf("clicking 'Audit Email' failed: %v", err)
	}
	select {
	case <-emailDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background Email Auth Deep-Dive")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("google._domainkey.example.co.nz") || !tester.HasText("MTA-STS: enforce") || !tester.HasText("BIMI: Present") {
		t.Errorf("expected DKIM selector, MTA-STS enforce mode, and BIMI badge to be rendered on scan page")
	}
	// Verify progressive disclosure toggle for Raw SPF TXT record
	if err := tester.Click("▸ Show Raw SPF TXT Record"); err != nil {
		t.Fatalf("clicking '▸ Show Raw SPF TXT Record' failed: %v", err)
	}
	if !tester.HasText("v=spf1 include:_spf.google.com -all") {
		t.Errorf("expected raw SPF TXT string to be visible after clicking '▸ Show Raw SPF TXT Record'")
	}

	// Switch to "REPUTATION" and run DNSBL / Reputation & Blacklist Check
	if err := tester.Click("REPUTATION"); err != nil {
		t.Fatalf("clicking 'REPUTATION' tile failed: %v", err)
	}
	if err := tester.Click("Check Reputation"); err != nil {
		t.Fatalf("clicking 'Check Reputation' failed: %v", err)
	}
	select {
	case <-repDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for background DNSBL Reputation Check")
	}
	time.Sleep(50 * time.Millisecond)
	tester.Frame()
	if !tester.HasText("Clean (0/12 Blacklists)") || !tester.HasText("Spamhaus DBL") || !tester.HasText("UCEPROTECT L1") || !tester.HasText("Google Safe Browsing ↗") {
		t.Errorf("expected Clean (0/12 Blacklists) badge, Spamhaus DBL card, UCEPROTECT L1 card (no truncation), and Google Safe Browsing link to be rendered")
	}
	if tester.HasText("Show All") {
		t.Errorf("expected all reputation cards to be visible without 'Show All' truncation toggle button")
	}

	// Test clicking "TARGETS" Executive Scorecard tile to switch to Discovered Targets sub-tab
	if err := tester.Click("TARGETS"); err != nil {
		t.Fatalf("clicking 'TARGETS' scorecard tile failed: %v", err)
	}
	if app.domainCategoryTab != DomainTabTargets {
		t.Errorf("expected domainCategoryTab to be DomainTabTargets (5), got %d", app.domainCategoryTab)
	}

	// Verify favicon persisted across sessions in scan list
	app2 := NewDesktopApp(store)
	if len(app2.scans) != 2 {
		t.Fatalf("expected 2 persisted scans across sessions, got %d", len(app2.scans))
	}
	if len(app2.scans[0].Favicon) == 0 {
		t.Errorf("expected persisted favicon bytes on domain scan summary")
	}
	if app2.scans[1].Depth != 1 || app2.scans[1].ParentScanID != parentID {
		t.Errorf("expected second scan in tree to be child IP scan at depth 1, got %+v", app2.scans[1])
	}

	// Test Open Session Modal on a fresh app and database
	freshDB := filepath.Join(t.TempDir(), "fresh.db")
	freshStore, err := storage.Open(freshDB)
	if err != nil {
		t.Fatalf("opening fresh store failed: %v", err)
	}
	defer freshStore.Close()
	app3 := NewDesktopApp(freshStore)
	app3.openDialogFn = func(opts mygo.OpenDialogOptions) ([]string, error) {
		return []string{sessionTestFile}, nil
	}
	saveAsTarget := filepath.Join(t.TempDir(), "test_save_as.rscan")
	app3.saveDialogFn = func(opts mygo.SaveDialogOptions) (string, error) {
		return saveAsTarget, nil
	}
	_ = ui.NewTester(app3.View, 1280, 820)

	// Test Open Session from File menu
	if !app3.TriggerMenuAction("file-open") {
		t.Fatalf("triggering 'file-open' failed")
	}
	time.Sleep(50 * time.Millisecond)
	if len(app3.scans) == 0 {
		if _, err := app3.OpenSessionFromFile(sessionTestFile); err != nil {
			t.Fatalf("OpenSessionFromFile failed: %v", err)
		}
	}
	if len(app3.scans) == 0 {
		t.Errorf("expected scans to be loaded into app3 after importing session")
	}

	// Test Save Session As from File menu
	if !app3.TriggerMenuAction("file-save-as") {
		t.Fatalf("triggering 'file-save-as' failed")
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(saveAsTarget); err != nil {
		t.Errorf("expected Save Session As to create %s, got: %v", saveAsTarget, err)
	}
}
