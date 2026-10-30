package main

import (
	"fmt"
	"strings"
	"sync"

	"domain-analyzer/analyzer"
	"domain-analyzer/storage"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// ScanRunnerFunc abstracts domain and IP scanning so unit tests can inject fast mocks if desired.
type ScanRunnerFunc struct {
	AnalyzeDomain func(domain string, checkVulns bool) *analyzer.DomainInfo
	AnalyzeIP     func(ip string, checkVulns bool) *analyzer.IPInfo
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

	mu sync.Mutex
}

func NewDesktopApp(store *storage.Store) *DesktopApp {
	app := &DesktopApp{
		store:          store,
		sidebarWidth:   320,
		scannedTargets: make(map[string]int64),
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
		return
	}
	rec, err := app.store.GetScan(id)
	if err != nil {
		app.statusText = fmt.Sprintf("Error loading scan #%d: %v", id, err)
		return
	}
	app.currentScan = rec
	app.rawJSONReadOnly = rec.RawJSON
	if rec.TargetType == analyzer.TargetTypeIP {
		app.currentPivots = analyzer.ExtractIPPivots(rec.IPInfo)
	} else {
		app.currentPivots = analyzer.ExtractDomainPivots(rec.DomainInfo)
	}
	if children, err := app.store.GetChildScans(id); err == nil {
		app.childScans = children
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
				c.WriteClipboard(scan.RawJSON)
				c.Toast("Copied scan JSON to clipboard")
			}

			if ui.Button(c, "Delete").Clicked() {
				idToDelete := scan.ID
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
	ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		ui.Text(c, key+":").FontSize(12).TextColor(t.TextMuted).MinWidth(140)
		ui.Text(c, val).FontSize(13).Selectable()
	})
}

func (app *DesktopApp) renderDomainDetails(c *ui.Context, t *ui.Theme, scanID int64, info *analyzer.DomainInfo) {
	// 1. Domain Registration & Overview
	app.renderSectionCard(c, t, "Registration & Domain Overview", func() {
		app.renderKeyValue(c, t, "Domain", info.Domain)
		if info.ApexDomain != "" && !strings.EqualFold(info.ApexDomain, info.Domain) {
			app.renderPivotActionRow(c, t, scanID, "Apex Domain", info.ApexDomain, "Apex Domain")
		} else {
			app.renderKeyValue(c, t, "Apex Domain", info.ApexDomain)
		}
		app.renderKeyValue(c, t, "Registrar", info.Registrar)
		app.renderKeyValue(c, t, "Expiration Date", info.ExpiryDate)
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

	// 3. WAF & Edge Protection (with CNAME chain drill-downs)
	app.renderSectionCard(c, t, "WAF & Edge Protection", func() {
		app.renderKeyValue(c, t, "WAF Summary", info.WAF.Summary)
		if info.WAF.BaselineStatus > 0 || info.WAF.ProbeStatus > 0 {
			app.renderKeyValue(c, t, "HTTP Probe Status", fmt.Sprintf("Baseline: HTTP %d → XSS Probe: HTTP %d", info.WAF.BaselineStatus, info.WAF.ProbeStatus))
		}

		if len(info.WAF.CNAMEs) > 0 {
			ui.Text(c, "CNAME Chain (Drill-Down):").FontSize(12).TextColor(t.TextMuted)
			for _, cname := range info.WAF.CNAMEs {
				app.renderPivotActionRow(c, t, scanID, "", cname, "CNAME")
			}
		}

		for _, prov := range info.WAF.Providers {
			ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
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

	// 5. Web Tech Stack & Security Headers
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

		if len(info.Web.SecurityHeaders) > 0 {
			ui.Text(c, "HTTP Security Headers:").FontSize(12).TextColor(t.TextMuted)
			for k, v := range info.Web.SecurityHeaders {
				app.renderKeyValue(c, t, k, v)
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
		if len(info.Web.TechStack) > 0 {
			app.renderKeyValue(c, t, "Detected Tech Stack", strings.Join(info.Web.TechStack, ", "))
		} else {
			app.renderKeyValue(c, t, "Detected Tech Stack", "None fingerprinted")
		}
		if len(info.Web.SecurityHeaders) > 0 {
			for k, v := range info.Web.SecurityHeaders {
				app.renderKeyValue(c, t, k, v)
			}
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
	app.renderSectionCard(c, t, "Persisted JSON Payload", func() {
		ui.TextArea(c, &app.rawJSONReadOnly).ReadOnly(true).Lines(18, 40).FillWidth()
	})
}
