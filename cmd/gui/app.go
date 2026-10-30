package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"domain-analyzer/analyzer"
	"domain-analyzer/storage"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// Canonical order for HTTP Security Headers so they never jump around on mouse movement / frame redraws.
var canonicalSecurityHeaderOrder = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

type headerPair struct {
	Key   string
	Value string
}

func sortedSecurityHeaders(headers map[string]string) []headerPair {
	if len(headers) == 0 {
		return nil
	}
	var out []headerPair
	seen := make(map[string]bool, len(headers))

	for _, k := range canonicalSecurityHeaderOrder {
		if v, ok := headers[k]; ok {
			out = append(out, headerPair{Key: k, Value: v})
			seen[k] = true
		}
	}

	var extras []string
	for k := range headers {
		if !seen[k] {
			extras = append(extras, k)
		}
	}
	sort.Strings(extras)
	for _, k := range extras {
		out = append(out, headerPair{Key: k, Value: headers[k]})
	}
	return out
}

// WhoisBrowserURL returns the full WHOIS browser lookup label and URL for a domain.
// For .nz domains, it uses https://dnc.org.nz/whois/whois-lookup/?domain_name=DOMAINNAME.nz
func WhoisBrowserURL(domain string, apexDomain string) (label string, whoisURL string) {
	lookupDomain := analyzer.CleanDomainTarget(apexDomain)
	if lookupDomain == "" {
		lookupDomain = analyzer.CleanDomainTarget(domain)
	}
	if lookupDomain == "" {
		return "", ""
	}
	if strings.HasSuffix(strings.ToLower(lookupDomain), ".nz") {
		return "Open Full .nz WHOIS (DNC) ↗", "https://dnc.org.nz/whois/whois-lookup/?domain_name=" + url.QueryEscape(lookupDomain)
	}
	return "Open Full WHOIS in Browser ↗", "https://lookup.icann.org/en/lookup?name=" + url.QueryEscape(lookupDomain)
}

type owaspChallengeLink struct {
	Label string
	URL   string
}

func buildOWASPChallengeLinks(target string, wafInfo analyzer.WAFInfo) []owaspChallengeLink {
	baseURL := strings.TrimSpace(wafInfo.BaselineURL)
	if baseURL == "" {
		clean := analyzer.NormalizeTarget(target)
		if clean == "" {
			return nil
		}
		baseURL = "https://" + clean
	}

	appendQuery := func(base, param string) string {
		if strings.Contains(base, "?") {
			return base + "&" + param
		}
		return base + "?" + param
	}

	probeURL := strings.TrimSpace(wafInfo.ProbeURL)
	if probeURL == "" {
		probeURL = appendQuery(baseURL, "probe_test=%3Cscript%3Ealert(1)%3C/script%3E")
	}

	return []owaspChallengeLink{
		{
			Label: "Baseline URL ↗",
			URL:   baseURL,
		},
		{
			Label: "OWASP XSS Challenge ↗",
			URL:   probeURL,
		},
		{
			Label: "OWASP SQLi Challenge ↗",
			URL:   appendQuery(baseURL, "id=1%27%20OR%20%271%27%3D%271"),
		},
		{
			Label: "OWASP Path Traversal Challenge ↗",
			URL:   appendQuery(baseURL, "file=..%2F..%2Fetc%2Fpasswd"),
		},
	}
}

// ScanRunnerFunc abstracts domain and IP scanning so unit tests can inject fast mocks if desired.
type ScanRunnerFunc struct {
	AnalyzeDomain func(domain string, checkVulns bool) *analyzer.DomainInfo
	AnalyzeIP     func(ip string, checkVulns bool) *analyzer.IPInfo
}

type cachedFavicon struct {
	attempted bool
	img       ui.ImageSource
	svg       *ui.SVG
}

type DesktopApp struct {
	store  *storage.Store
	win    *mygo.Window
	runner ScanRunnerFunc

	// UI state (accessed on UI thread)
	sidebarWidth float32
	targetInput  string
	checkVulns   bool
	searchQuery  string
	activeTab    int

	scanning   bool
	statusText string

	scans           []storage.ScanSummary
	currentScan     *storage.ScanRecord
	currentPivots   []analyzer.PivotTarget
	childScans      []storage.ScanSummary
	scannedTargets  map[string]int64
	rawJSONReadOnly string
	jsonSpansDark   []ui.Span
	jsonSpansLight  []ui.Span
	faviconCache    map[int64]cachedFavicon

	mu sync.Mutex
}

func NewDesktopApp(store *storage.Store) *DesktopApp {
	app := &DesktopApp{
		store:          store,
		sidebarWidth:   330,
		scannedTargets: make(map[string]int64),
		faviconCache:   make(map[int64]cachedFavicon),
		runner: ScanRunnerFunc{
			AnalyzeDomain: analyzer.Analyze,
			AnalyzeIP:     analyzer.AnalyzeIP,
		},
	}
	app.RefreshHistory()
	if len(app.scans) > 0 {
		app.SelectScan(app.scans[0].ID)
	}
	return app
}

func (app *DesktopApp) SetWindow(win *mygo.Window) {
	app.win = win
}

func (app *DesktopApp) runOnUI(fn func()) {
	if app.win != nil {
		app.win.Update(fn)
	} else {
		fn()
	}
}

func (app *DesktopApp) RefreshHistory() {
	if app.store == nil {
		return
	}
	if list, err := app.store.ListScans(app.searchQuery); err == nil {
		app.scans = list
	}
	if latest, err := app.store.LatestScansByTarget(); err == nil {
		app.scannedTargets = latest
	}
	if app.currentScan != nil {
		if children, err := app.store.GetChildScans(app.currentScan.ID); err == nil {
			app.childScans = children
		}
	}
}

func (app *DesktopApp) SelectScan(id int64) {
	if app.store == nil || id <= 0 {
		app.currentScan = nil
		app.currentPivots = nil
		app.childScans = nil
		app.rawJSONReadOnly = ""
		app.jsonSpansDark = nil
		app.jsonSpansLight = nil
		return
	}
	rec, err := app.store.GetScan(id)
	if err != nil {
		app.statusText = fmt.Sprintf("Error loading scan #%d: %v", id, err)
		return
	}
	app.currentScan = rec
	app.rawJSONReadOnly = formatJSONPretty(rec.RawJSON)
	app.jsonSpansDark = highlightJSON(app.rawJSONReadOnly, true)
	app.jsonSpansLight = highlightJSON(app.rawJSONReadOnly, false)

	if rec.TargetType == analyzer.TargetTypeIP {
		app.currentPivots = analyzer.ExtractIPPivots(rec.IPInfo)
	} else {
		app.currentPivots = analyzer.ExtractDomainPivots(rec.DomainInfo)
	}
	if children, err := app.store.GetChildScans(id); err == nil {
		app.childScans = children
	}
}

// renderFavicon renders the decoded website favicon if present for a scan.
func (app *DesktopApp) renderFavicon(c *ui.Context, scanID int64, raw []byte, size float32) {
	if len(raw) == 0 {
		return
	}
	entry, ok := app.faviconCache[scanID]
	if !ok {
		entry.attempted = true
		trimmed := bytes.TrimSpace(raw)
		if bytes.HasPrefix(trimmed, []byte("<svg")) || (bytes.HasPrefix(trimmed, []byte("<?xml")) && bytes.Contains(trimmed, []byte("<svg"))) {
			if svg, err := ui.ParseSVG(trimmed); err == nil {
				entry.svg = svg
			}
		} else {
			normalized := analyzer.NormalizeFaviconBytes(raw)
			if len(normalized) > 0 {
				if img, err := ui.DecodeImage(normalized); err == nil {
					entry.img = img
				}
			}
		}
		app.faviconCache[scanID] = entry
	}

	if entry.img != nil {
		ui.Image(c, entry.img).Size(size, size).Radius(3)
	} else if entry.svg != nil {
		ui.Icon(c, entry.svg).Size(size, size)
	}
}

// StartScan launches a domain or IP scan asynchronously and persists the result to SQLite.
func (app *DesktopApp) StartScan(rawTarget string, parentID int64, reason string) {
	target := analyzer.NormalizeTarget(rawTarget)
	if target == "" || app.scanning {
		return
	}

	checkVulns := app.checkVulns
	isIP := analyzer.IsIPAddress(target)
	if !isIP {
		target = analyzer.CleanDomainTarget(target)
	}

	app.scanning = true
	kindLabel := "domain"
	if isIP {
		kindLabel = "IP"
	}
	if reason != "" {
		app.statusText = fmt.Sprintf("Scanning %s %s (via %s)...", kindLabel, target, reason)
	} else {
		app.statusText = fmt.Sprintf("Scanning %s %s...", kindLabel, target)
	}

	go func() {
		var savedID int64
		var saveErr error

		if isIP {
			info := app.runner.AnalyzeIP(target, checkVulns)
			if app.store != nil {
				savedID, saveErr = app.store.SaveIPScan(info, parentID, reason, checkVulns)
			}
		} else {
			info := app.runner.AnalyzeDomain(target, checkVulns)
			if app.store != nil {
				savedID, saveErr = app.store.SaveDomainScan(info, parentID, reason, checkVulns)
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Scan error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Completed scan of %s", target)
			app.RefreshHistory()
			if savedID > 0 {
				app.SelectScan(savedID)
			}
		})
	}()
}

func (app *DesktopApp) View(c *ui.Context) {
	t := c.Theme()

	ui.Column(c).Fill().Background(t.Background).Children(func() {
		// Top Toolbar
		app.renderTopBar(c, t)
		ui.Divider(c)

		// Main Split View: History Sidebar (left) | Scan Inspector (right)
		ui.Split(c, &app.sidebarWidth, func() {
			app.renderSidebar(c, t)
		}, func() {
			app.renderDetailPane(c, t)
		}).Grow(1).FillWidth()
	})
}

func (app *DesktopApp) renderTopBar(c *ui.Context, t *ui.Theme) {
	ui.Row(c).FillWidth().Padding(12).Gap(10).AlignItems(ui.Center).Background(t.Surface).Children(func() {
		ui.Text(c, "Domain Analyzer").FontSize(17).Bold()

		inp := ui.TextInput(c, &app.targetInput).
			Placeholder("Enter domain (e.g. example.com) or IP (e.g. 93.184.216.34)...").
			Grow(1)
		if inp.Submitted() && strings.TrimSpace(app.targetInput) != "" && !app.scanning {
			target := app.targetInput
			app.StartScan(target, 0, "")
		}

		ui.Checkbox(c, &app.checkVulns, "Check CVEs")

		if ui.PrimaryButton(c, "Scan Target").Disabled(app.scanning || strings.TrimSpace(app.targetInput) == "").Clicked() {
			app.StartScan(app.targetInput, 0, "")
		}

		if app.scanning {
			ui.Spinner(c)
		}
		if app.statusText != "" {
			ui.Text(c, app.statusText).FontSize(12).TextColor(t.TextMuted)
		}
	})
}

func (app *DesktopApp) renderSidebar(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Fill().Padding(10).Gap(8).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			ui.Text(c, "Saved Scans").FontSize(14).Bold()
			ui.Spacer(c)
			ui.Badge(c, fmt.Sprintf("%d", len(app.scans)))
		})

		if ui.SearchField(c, &app.searchQuery).Placeholder("Filter history...").FillWidth().Changed() {
			app.RefreshHistory()
		}

		ui.Scroll(c).Grow(1).FillWidth().Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				if len(app.scans) == 0 {
					ui.Text(c, "No scans saved yet. Enter a domain or IP above to start.").
						FontSize(12).
						TextColor(t.TextMuted)
					return
				}

				for _, item := range app.scans {
					scanItem := item
					isSelected := app.currentScan != nil && app.currentScan.ID == scanItem.ID

					cardBg := t.Surface
					borderCol := t.Border
					if isSelected {
						borderCol = t.Accent
					}

					card := ui.Box(c).
						Key(scanItem.ID).
						FillWidth().
						Padding(10).
						Radius(6).
						Background(cardBg).
						Border(1, borderCol).
						Cursor(ui.CursorPointer)

					card.Children(func() {
						ui.Column(c).FillWidth().Gap(4).Children(func() {
							ui.Row(c).FillWidth().Gap(6).AlignItems(ui.Center).Children(func() {
								app.renderFavicon(c, scanItem.ID, scanItem.Favicon, 16)

								typeBadge := "DOMAIN"
								if scanItem.TargetType == analyzer.TargetTypeIP {
									typeBadge = "IP"
								}
								ui.Badge(c, typeBadge)
								ui.Text(c, scanItem.Target).Bold().FontSize(13)
							})

							if scanItem.PivotReason != "" {
								ui.Text(c, fmt.Sprintf("↳ Pivot via %s", scanItem.PivotReason)).
									FontSize(11).
									TextColor(t.Accent)
							}

							if scanItem.Summary != "" {
								ui.Text(c, scanItem.Summary).
									FontSize(11).
									TextColor(t.TextMuted).
									MaxLines(1).
									Ellipsis("...")
							}

							ui.Text(c, scanItem.CreatedAt.Local().Format("2006-01-02 15:04:05")).
								FontSize(10).
								TextColor(t.TextMuted)
						})
					})

					if card.Clicked() {
						app.SelectScan(scanItem.ID)
					}
				}
			})
		})
	})
}

func (app *DesktopApp) renderDetailPane(c *ui.Context, t *ui.Theme) {
	if app.currentScan == nil {
		ui.Column(c).Fill().Center().Gap(10).Padding(24).Children(func() {
			ui.Text(c, "Select a scan from the left sidebar or start a new scan above.").
				FontSize(15).
				TextColor(t.TextMuted)
		})
		return
	}

	scan := app.currentScan

	ui.Column(c).Fill().Padding(14).Gap(10).Children(func() {
		// Scan Header & Lineage Controls
		ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
			if scan.ParentScanID > 0 {
				if ui.Button(c, "← Parent Scan").Clicked() {
					app.SelectScan(scan.ParentScanID)
					return
				}
			}

			app.renderFavicon(c, scan.ID, scan.Favicon, 20)

			badgeLabel := "DOMAIN SCAN"
			if scan.TargetType == analyzer.TargetTypeIP {
				badgeLabel = "IP SCAN"
			}
			ui.Badge(c, badgeLabel)
			ui.Text(c, scan.Target).FontSize(20).Bold().Selectable()

			if scan.PivotReason != "" {
				ui.Badge(c, "via "+scan.PivotReason)
			}

			ui.Spacer(c)

			if ui.Button(c, "Re-scan ↻").Disabled(app.scanning).Clicked() {
				app.StartScan(scan.Target, scan.ParentScanID, scan.PivotReason)
			}

			if ui.Button(c, "Copy JSON").Clicked() {
				c.WriteClipboard(app.rawJSONReadOnly)
				c.Toast("Copied scan JSON to clipboard")
			}

			if ui.Button(c, "Delete").Clicked() {
				idToDelete := scan.ID
				delete(app.faviconCache, idToDelete)
				_ = app.store.DeleteScan(idToDelete)
				app.RefreshHistory()
				if len(app.scans) > 0 {
					app.SelectScan(app.scans[0].ID)
				} else {
					app.SelectScan(0)
				}
				return
			}
		})

		ui.Text(c, fmt.Sprintf("Scanned at %s • Discovered %d drill-down targets • %d child scans",
			scan.CreatedAt.Local().Format("2006-01-02 15:04:05"),
			len(app.currentPivots),
			len(app.childScans),
		)).FontSize(12).TextColor(t.TextMuted)

		// Navigation Tabs
		tabLabels := []string{
			"Overview & Details",
			fmt.Sprintf("Discovered Targets (%d)", len(app.currentPivots)),
			fmt.Sprintf("Child Scans (%d)", len(app.childScans)),
			"Raw JSON",
		}
		ui.Tabs(c, &app.activeTab, tabLabels...)

		ui.Scroll(c).Grow(1).FillWidth().Children(func() {
			ui.Column(c).FillWidth().Gap(12).PaddingY(6).Children(func() {
				switch app.activeTab {
				case 0:
					if scan.TargetType == analyzer.TargetTypeIP && scan.IPInfo != nil {
						app.renderIPDetails(c, t, scan.ID, scan.IPInfo)
					} else if scan.DomainInfo != nil {
						app.renderDomainDetails(c, t, scan.ID, scan.DomainInfo)
					}
				case 1:
					app.renderPivotsTab(c, t, scan.ID)
				case 2:
					app.renderChildScansTab(c, t)
				case 3:
					app.renderRawJSONTab(c, t)
				}
			})
		})
	})
}

// renderPivotActionRow renders a discovered domain or IP with one-click "Scan ↗" and (if previously scanned) "View Scan ✓" buttons.
func (app *DesktopApp) renderPivotActionRow(c *ui.Context, t *ui.Theme, parentScanID int64, label string, target string, reason string) {
	cleanTarget := strings.TrimSpace(target)
	if cleanTarget == "" {
		return
	}
	lookupKey := strings.ToLower(cleanTarget)
	if !analyzer.IsIPAddress(cleanTarget) {
		lookupKey = analyzer.CleanDomainTarget(cleanTarget)
	}
	existingScanID := app.scannedTargets[lookupKey]

	ui.Row(c).Key("pivot:" + reason + ":" + lookupKey).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		if label != "" {
			ui.Text(c, label+":").FontSize(12).TextColor(t.TextMuted).MinWidth(130)
		}
		ui.Text(c, cleanTarget).FontSize(13).Bold().Selectable()
		ui.Badge(c, reason)

		ui.Spacer(c)

		if existingScanID > 0 && (app.currentScan == nil || existingScanID != app.currentScan.ID) {
			if ui.Button(c, "View Scan ✓").Clicked() {
				app.SelectScan(existingScanID)
			}
		}

		btnLabel := "Scan Domain ↗"
		if analyzer.IsIPAddress(cleanTarget) {
			btnLabel = "Scan IP ↗"
		}
		if ui.Button(c, btnLabel).Disabled(app.scanning).Clicked() {
			app.StartScan(lookupKey, parentScanID, reason)
		}
	})
}

func (app *DesktopApp) renderSectionCard(c *ui.Context, t *ui.Theme, title string, children func()) {
	ui.Box(c).FillWidth().Padding(12).Radius(8).Background(t.Surface).Border(1, t.Border).Children(func() {
		ui.Column(c).FillWidth().Gap(8).Children(func() {
			ui.Text(c, title).FontSize(14).Bold()
			ui.Divider(c)
			children()
		})
	})
}

func (app *DesktopApp) renderKeyValue(c *ui.Context, t *ui.Theme, key string, val string) {
	if val == "" {
		val = "N/A"
	}
	ui.Row(c).Key("kv:" + key).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		ui.Text(c, key+":").FontSize(12).TextColor(t.TextMuted).MinWidth(140)
		ui.Text(c, val).FontSize(13).Selectable()
	})
}

func (app *DesktopApp) renderDomainDetails(c *ui.Context, t *ui.Theme, scanID int64, info *analyzer.DomainInfo) {
	// 1. Domain Registration & Overview (with Full WHOIS Browser Link)
	app.renderSectionCard(c, t, "Registration & Domain Overview", func() {
		app.renderKeyValue(c, t, "Domain", info.Domain)
		if info.ApexDomain != "" && !strings.EqualFold(info.ApexDomain, info.Domain) {
			app.renderPivotActionRow(c, t, scanID, "Apex Domain", info.ApexDomain, "Apex Domain")
		} else {
			app.renderKeyValue(c, t, "Apex Domain", info.ApexDomain)
		}
		app.renderKeyValue(c, t, "Registrar", info.Registrar)
		app.renderKeyValue(c, t, "Expiration Date", info.ExpiryDate)

		whoisLabel, whoisURL := WhoisBrowserURL(info.Domain, info.ApexDomain)
		if whoisURL != "" {
			ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, "External WHOIS:").FontSize(12).TextColor(t.TextMuted).MinWidth(140)
				ui.Link(c, whoisLabel, whoisURL)
			})
		}
	})

	// 2. DNS & IP Infrastructure (with IP & NS drill-downs)
	app.renderSectionCard(c, t, "DNS & IP Infrastructure", func() {
		if info.DNS.IPAddress != "" {
			app.renderPivotActionRow(c, t, scanID, "A Record IP", info.DNS.IPAddress, "A Record")
			app.renderKeyValue(c, t, "IP Owner & TTL", fmt.Sprintf("%s (TTL: %ds)", info.DNS.IPOwner, info.DNS.IPTTL))
		} else {
			app.renderKeyValue(c, t, "A Record IP", "None resolved")
		}

		if info.DNS.WWWAddress != "" {
			app.renderPivotActionRow(c, t, scanID, "WWW Record IP", info.DNS.WWWAddress, "WWW Record")
		}

		if len(info.DNS.NSProviders) > 0 {
			app.renderKeyValue(c, t, "NS Providers", strings.Join(info.DNS.NSProviders, ", "))
		}

		if len(info.DNS.Nameservers) > 0 {
			ui.Text(c, "Nameservers:").FontSize(12).TextColor(t.TextMuted)
			for _, ns := range info.DNS.Nameservers {
				app.renderPivotActionRow(c, t, scanID, "", ns, "Nameserver")
			}
		}

		if info.DNS.CAARecord != nil && len(info.DNS.CAARecord.RawRecords) > 0 {
			app.renderKeyValue(c, t, "CAA Records", strings.Join(info.DNS.CAARecord.RawRecords, "; "))
		}
	})

	// 3. WAF & Edge Protection (with CNAME chain drill-downs & OWASP Browser Challenges)
	app.renderSectionCard(c, t, "WAF & Edge Protection", func() {
		app.renderKeyValue(c, t, "WAF Summary", info.WAF.Summary)
		if info.WAF.BaselineStatus > 0 || info.WAF.ProbeStatus > 0 {
			app.renderKeyValue(c, t, "HTTP Probe Status", fmt.Sprintf("Baseline: HTTP %d → XSS Probe: HTTP %d", info.WAF.BaselineStatus, info.WAF.ProbeStatus))
		}

		// OWASP Passive/Challenge Links in Default Browser
		challenges := buildOWASPChallengeLinks(info.Domain, info.WAF)
		if len(challenges) > 0 {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, "OWASP Browser Challenges:").FontSize(12).TextColor(t.TextMuted).MinWidth(140)
				for _, ch := range challenges {
					ui.Link(c, ch.Label, ch.URL)
				}
			})
		}

		if len(info.WAF.CNAMEs) > 0 {
			ui.Text(c, "CNAME Chain (Drill-Down):").FontSize(12).TextColor(t.TextMuted)
			for _, cname := range info.WAF.CNAMEs {
				app.renderPivotActionRow(c, t, scanID, "", cname, "CNAME")
			}
		}

		for _, prov := range info.WAF.Providers {
			ui.Box(c).Key("wafprov:"+prov.Provider).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
				ui.Column(c).FillWidth().Gap(4).Children(func() {
					ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
						ui.Text(c, prov.Provider).Bold()
						ui.Badge(c, prov.State)
					})
					if len(prov.Implementation) > 0 {
						ui.Text(c, "Implementation: "+strings.Join(prov.Implementation, " | ")).FontSize(12)
					}
					if len(prov.Evidence) > 0 {
						ui.Text(c, "Evidence: "+strings.Join(prov.Evidence, ", ")).FontSize(11).TextColor(t.TextMuted)
					}
				})
			})
		}

		for _, note := range info.WAF.OriginNotes {
			ui.Text(c, "Origin Note: "+note).FontSize(12)
		}
	})

	// 4. TLS Certificate & Subject Alternative Names (SAN drill-downs)
	app.renderSectionCard(c, t, "TLS Certificate & Discovered SAN Domains", func() {
		if !info.TLS.HasTLS {
			ui.Text(c, "No TLS certificate detected on port 443.").FontSize(12).TextColor(t.TextMuted)
			return
		}
		app.renderKeyValue(c, t, "TLS Issuer", info.TLS.TLSIssuer)
		app.renderKeyValue(c, t, "TLS Expiry", info.TLS.TLSExpiry)

		if len(info.TLS.SANDomains) > 0 {
			ui.Text(c, fmt.Sprintf("Subject Alternative Names (%d):", len(info.TLS.SANDomains))).
				FontSize(12).
				TextColor(t.TextMuted)
			for _, san := range info.TLS.SANDomains {
				app.renderPivotActionRow(c, t, scanID, "", san, "TLS SAN")
			}
		}
	})

	// 5. Web Tech Stack & Security Headers (Deterministically ordered!)
	app.renderSectionCard(c, t, "Web Technologies & Security Headers", func() {
		if len(info.Web.TechDetails) > 0 {
			var techFormatted []string
			for _, td := range info.Web.TechDetails {
				if td.Version != "" {
					techFormatted = append(techFormatted, fmt.Sprintf("%s (%s)", td.Name, td.Version))
				} else {
					techFormatted = append(techFormatted, td.Name)
				}
			}
			app.renderKeyValue(c, t, "Detected Tech Stack", strings.Join(techFormatted, ", "))
		} else {
			app.renderKeyValue(c, t, "Detected Tech Stack", "None fingerprinted")
		}

		orderedHeaders := sortedSecurityHeaders(info.Web.SecurityHeaders)
		if len(orderedHeaders) > 0 {
			ui.Text(c, "HTTP Security Headers:").FontSize(12).TextColor(t.TextMuted)
			for _, kv := range orderedHeaders {
				app.renderKeyValue(c, t, kv.Key, kv.Value)
			}
		}
	})

	// 6. Email Security (MX, SPF, DMARC)
	app.renderSectionCard(c, t, "Email Providers, SPF & DMARC", func() {
		if len(info.Email.MailProviders) > 0 {
			app.renderKeyValue(c, t, "Mail Providers", strings.Join(info.Email.MailProviders, ", "))
		} else {
			app.renderKeyValue(c, t, "Mail Providers", "None detected")
		}

		if info.Email.SPFRecord != nil {
			app.renderKeyValue(c, t, "SPF Status", fmt.Sprintf("%s — %s (%s)", info.Email.SPFRecord.Status, info.Email.SPFRecord.Policy, info.Email.SPFRecord.Description))
			app.renderKeyValue(c, t, "SPF Raw", info.Email.SPFRecord.Raw)
			if len(info.Email.SPFRecord.Includes) > 0 {
				ui.Text(c, "SPF Includes (Drill-Down):").FontSize(12).TextColor(t.TextMuted)
				for _, inc := range info.Email.SPFRecord.Includes {
					app.renderPivotActionRow(c, t, scanID, "", inc, "SPF Include")
				}
			}
		}

		if info.Email.DMARCRecord != nil {
			app.renderKeyValue(c, t, "DMARC Status", fmt.Sprintf("%s — Policy: %s (%s)", info.Email.DMARCRecord.Status, info.Email.DMARCRecord.Policy, info.Email.DMARCRecord.Description))
			app.renderKeyValue(c, t, "DMARC Raw", info.Email.DMARCRecord.Raw)
		}
	})

	// 7. Vulnerabilities (CVEs)
	if len(info.Vulnerabilities) > 0 {
		app.renderVulnerabilitiesCard(c, t, info.Vulnerabilities)
	}
}

func (app *DesktopApp) renderIPDetails(c *ui.Context, t *ui.Theme, scanID int64, info *analyzer.IPInfo) {
	// 1. IP WHOIS & Network Ownership
	app.renderSectionCard(c, t, "IP Ownership & Network Details", func() {
		app.renderKeyValue(c, t, "IP Address", info.IP)
		app.renderKeyValue(c, t, "Organization / Owner", info.Owner)
		app.renderKeyValue(c, t, "ASN", info.ASN)
		app.renderKeyValue(c, t, "CIDR / NetRange", info.CIDR)
		app.renderKeyValue(c, t, "Country", info.Country)

		if info.IP != "" {
			ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, "External WHOIS:").FontSize(12).TextColor(t.TextMuted).MinWidth(140)
				ui.Link(c, "Open Full IP WHOIS in Browser ↗", "https://who.is/whois-ip/ip-address/"+url.PathEscape(info.IP))
			})
		}
	})

	// 2. Reverse DNS (PTR) Hostnames
	app.renderSectionCard(c, t, "Reverse DNS (PTR Hostnames)", func() {
		if len(info.PTRRecords) == 0 {
			ui.Text(c, "No PTR records found for this IP address.").FontSize(12).TextColor(t.TextMuted)
			return
		}
		for _, ptr := range info.PTRRecords {
			app.renderPivotActionRow(c, t, scanID, "PTR Hostname", ptr, "PTR Record")
		}
	})

	// 3. Direct TLS Inspection on :443
	app.renderSectionCard(c, t, "Direct TLS Inspection (:443) & Certificate Domains", func() {
		if !info.TLS.HasTLS {
			ui.Text(c, "No TLS service responded on port 443.").FontSize(12).TextColor(t.TextMuted)
			return
		}
		app.renderKeyValue(c, t, "TLS Issuer", info.TLS.TLSIssuer)
		app.renderKeyValue(c, t, "TLS Expiry", info.TLS.TLSExpiry)

		if len(info.TLS.SANDomains) > 0 {
			ui.Text(c, "Certificate Domains / SANs (Drill-Down):").FontSize(12).TextColor(t.TextMuted)
			for _, san := range info.TLS.SANDomains {
				app.renderPivotActionRow(c, t, scanID, "", san, "TLS SAN")
			}
		}
	})

	// 4. Direct HTTP / WAF / Tech Stack on IP
	app.renderSectionCard(c, t, "Direct HTTP, WAF & Tech Fingerprinting", func() {
		app.renderKeyValue(c, t, "WAF Summary", info.WAF.Summary)

		challenges := buildOWASPChallengeLinks(info.IP, info.WAF)
		if len(challenges) > 0 {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, "OWASP Browser Challenges:").FontSize(12).TextColor(t.TextMuted).MinWidth(140)
				for _, ch := range challenges {
					ui.Link(c, ch.Label, ch.URL)
				}
			})
		}

		if len(info.Web.TechStack) > 0 {
			app.renderKeyValue(c, t, "Detected Tech Stack", strings.Join(info.Web.TechStack, ", "))
		} else {
			app.renderKeyValue(c, t, "Detected Tech Stack", "None fingerprinted")
		}
		orderedHeaders := sortedSecurityHeaders(info.Web.SecurityHeaders)
		for _, kv := range orderedHeaders {
			app.renderKeyValue(c, t, kv.Key, kv.Value)
		}
	})

	if len(info.Vulnerabilities) > 0 {
		app.renderVulnerabilitiesCard(c, t, info.Vulnerabilities)
	}
}

func (app *DesktopApp) renderVulnerabilitiesCard(c *ui.Context, t *ui.Theme, vulns []analyzer.Vulnerability) {
	app.renderSectionCard(c, t, fmt.Sprintf("Detected Vulnerabilities (%d CVEs)", len(vulns)), func() {
		for _, v := range vulns {
			vuln := v
			ui.Box(c).Key(vuln.ID).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
				ui.Column(c).FillWidth().Gap(4).Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, vuln.ID).Bold()
						ui.Badge(c, vuln.Severity)
						ui.Spacer(c)
						if vuln.URL != "" {
							ui.Link(c, "NVD Advisory ↗", vuln.URL)
						}
					})
					ui.Text(c, vuln.Description).FontSize(12).TextColor(t.TextMuted)
				})
			})
		}
	})
}

func (app *DesktopApp) renderPivotsTab(c *ui.Context, t *ui.Theme, scanID int64) {
	if len(app.currentPivots) == 0 {
		ui.Text(c, "No additional domains or IP addresses were discovered in this scan.").
			FontSize(13).
			TextColor(t.TextMuted)
		return
	}

	app.renderSectionCard(c, t, "Discovered Domains & IP Addresses (Click to Drill Down)", func() {
		for _, pivot := range app.currentPivots {
			p := pivot
			typeLabel := "Domain"
			if p.Type == analyzer.TargetTypeIP {
				typeLabel = "IP Address"
			}
			app.renderPivotActionRow(c, t, scanID, typeLabel, p.Target, p.Reason)
		}
	})
}

func (app *DesktopApp) renderChildScansTab(c *ui.Context, t *ui.Theme) {
	if len(app.childScans) == 0 {
		ui.Text(c, "No subsequent scans have been drilled down from this scan yet. Click 'Scan Domain ↗' or 'Scan IP ↗' on any discovered target to pivot.").
			FontSize(13).
			TextColor(t.TextMuted)
		return
	}

	app.renderSectionCard(c, t, "Subsequent Scans Drilled Down From This Scan", func() {
		for _, child := range app.childScans {
			ch := child
			ui.Row(c).Key(ch.ID).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
				app.renderFavicon(c, ch.ID, ch.Favicon, 16)
				ui.Badge(c, string(ch.TargetType))
				ui.Text(c, ch.Target).Bold()
				if ch.PivotReason != "" {
					ui.Badge(c, "via "+ch.PivotReason)
				}
				ui.Text(c, ch.Summary).FontSize(12).TextColor(t.TextMuted)
				ui.Spacer(c)
				if ui.Button(c, "Open Scan →").Clicked() {
					app.SelectScan(ch.ID)
					app.activeTab = 0
				}
			})
		}
	})
}

func (app *DesktopApp) renderRawJSONTab(c *ui.Context, t *ui.Theme) {
	ui.Box(c).FillWidth().Padding(12).Radius(8).Background(t.Surface).Border(1, t.Border).Children(func() {
		ui.Column(c).FillWidth().Gap(8).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Formatted & Syntax-Highlighted JSON").FontSize(14).Bold()
				ui.Spacer(c)
				if ui.PrimaryButton(c, "Copy JSON to Clipboard").Clicked() {
					c.WriteClipboard(app.rawJSONReadOnly)
					c.Toast("Copied formatted JSON to clipboard")
				}
			})
			ui.Divider(c)

			spans := app.jsonSpansLight
			if t.Dark {
				spans = app.jsonSpansDark
			}
			ui.Box(c).FillWidth().Padding(12).Radius(6).Background(t.Background).Border(1, t.Border).Children(func() {
				ui.RichText(c, spans...).Font("monospace").FontSize(12).Selectable().FillWidth()
			})
		})
	})
}

func formatJSONPretty(raw string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(raw), "", "  "); err == nil {
		return buf.String()
	}
	return raw
}

// highlightJSON tokenizes pretty-printed JSON into syntax-highlighted ui.Span runs.
func highlightJSON(src string, dark bool) []ui.Span {
	var (
		colKey   = ui.RGB(5, 80, 174)
		colStr   = ui.RGB(17, 99, 41)
		colNum   = ui.RGB(149, 56, 0)
		colBool  = ui.RGB(130, 80, 223)
		colPunct = ui.RGB(100, 110, 120)
	)
	if dark {
		colKey = ui.RGB(121, 192, 255)
		colStr = ui.RGB(126, 231, 135)
		colNum = ui.RGB(255, 166, 87)
		colBool = ui.RGB(210, 168, 255)
		colPunct = ui.RGB(139, 148, 158)
	}

	var spans []ui.Span
	n := len(src)
	i := 0

	for i < n {
		ch := src[i]

		// String token (either object key or string value)
		if ch == '"' {
			start := i
			i++
			for i < n {
				if src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == '"' {
					i++
					break
				}
				i++
			}
			token := src[start:i]

			// Look ahead past spaces to see if followed by ':'
			j := i
			for j < n && (src[j] == ' ' || src[j] == '\t') {
				j++
			}
			isKey := j < n && src[j] == ':'

			if isKey {
				spans = append(spans, ui.Span{
					Text:   token,
					Font:   "monospace",
					Color:  colKey,
					Weight: 600,
				})
			} else {
				spans = append(spans, ui.Span{
					Text:  token,
					Font:  "monospace",
					Color: colStr,
				})
			}
			continue
		}

		// Number token
		if (ch >= '0' && ch <= '9') || ch == '-' {
			start := i
			i++
			for i < n && ((src[i] >= '0' && src[i] <= '9') || src[i] == '.' || src[i] == 'e' || src[i] == 'E' || src[i] == '+' || src[i] == '-') {
				i++
			}
			spans = append(spans, ui.Span{
				Text:  src[start:i],
				Font:  "monospace",
				Color: colNum,
			})
			continue
		}

		// Boolean or null literal
		if strings.HasPrefix(src[i:], "true") || strings.HasPrefix(src[i:], "false") || strings.HasPrefix(src[i:], "null") {
			litLen := 4
			if strings.HasPrefix(src[i:], "false") {
				litLen = 5
			}
			spans = append(spans, ui.Span{
				Text:   src[i : i+litLen],
				Font:   "monospace",
				Color:  colBool,
				Weight: 600,
			})
			i += litLen
			continue
		}

		// Punctuation & whitespace
		start := i
		for i < n {
			c := src[i]
			if c == '"' || (c >= '0' && c <= '9') || c == '-' ||
				strings.HasPrefix(src[i:], "true") || strings.HasPrefix(src[i:], "false") || strings.HasPrefix(src[i:], "null") {
				break
			}
			i++
		}
		spans = append(spans, ui.Span{
			Text:  src[start:i],
			Font:  "monospace",
			Color: colPunct,
		})
	}

	return spans
}
