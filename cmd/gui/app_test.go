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
	doneCh := make(chan struct{}, 4)
	portDoneCh := make(chan struct{}, 2)
	pingDoneCh := make(chan struct{}, 2)
	traceDoneCh := make(chan struct{}, 2)
	subDoneCh := make(chan struct{}, 2)
	metaDoneCh := make(chan struct{}, 2)
	tlsDoneCh := make(chan struct{}, 2)
	httpDoneCh := make(chan struct{}, 2)
	emailDoneCh := make(chan struct{}, 2)
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

	tester := ui.NewTester(app.View, 1280, 4200)

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

	// Test adjusting text size up and down in the GUI
	if !tester.HasText("100%") {
		t.Fatalf("expected default text size indicator '100%%'")
	}
	if err := tester.Click("A+"); err != nil {
		t.Fatalf("clicking 'A+' failed: %v", err)
	}
	if !tester.HasText("110%") {
		t.Errorf("expected text size indicator '110%%' after clicking A+")
	}
	if err := tester.Click("A-"); err != nil {
		t.Fatalf("clicking 'A-' failed: %v", err)
	}
	if !tester.HasText("100%") {
		t.Errorf("expected text size indicator '100%%' after clicking A-")
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

	// Verify child scan tree indicator in sidebar
	if !tester.HasText("└─") {
		t.Errorf("expected child scan tree indicator '└─' in sidebar")
	}

	// Run a host port scan on the IP scan result
	if err := tester.Click("Scan Host Ports"); err != nil {
		t.Fatalf("clicking 'Scan Host Ports' failed: %v", err)
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

	// Run Ping and Traceroute on the domain scan page
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

	// Run Passive Subdomain Enumeration on the domain scan page
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

	// Run Website Metadata & Well-Known Files inspection on the domain scan page
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

	// Run Deep TLS & Cipher Suite Audit on the domain scan page
	if err := tester.Click("Audit TLS & Ciphers"); err != nil {
		t.Fatalf("clicking 'Audit TLS & Ciphers' failed: %v", err)
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

	// Run HTTP Redirect Chain & Performance Timing Waterfall trace on the domain scan page
	if err := tester.Click("Trace Redirects & Timing"); err != nil {
		t.Fatalf("clicking 'Trace Redirects & Timing' failed: %v", err)
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

	// Run on-demand CVE check inside "Web Technologies & Security Headers"
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

	// Run Email Deliverability & Authentication Deep-Dive (DKIM, MTA-STS, TLS-RPT, BIMI)
	if err := tester.Click("Audit Email Auth"); err != nil {
		t.Fatalf("clicking 'Audit Email Auth' failed: %v", err)
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
}
