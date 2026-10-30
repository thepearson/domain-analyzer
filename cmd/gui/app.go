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

// ScanRunnerFunc abstracts domain, IP, port, ping, and traceroute operations so unit tests can inject fast mocks if desired.
type ScanRunnerFunc struct {
	AnalyzeDomain         func(domain string, checkVulns bool) *analyzer.DomainInfo
	AnalyzeIP             func(ip string, checkVulns bool) *analyzer.IPInfo
	ScanPorts             func(ip string) []analyzer.PortService
	RunPing               func(target string) *analyzer.PingResult
	RunTraceroute         func(target string) *analyzer.TracerouteResult
	EnumerateSubdomains   func(domain string) *analyzer.SubdomainEnumeration
	InspectMetadata       func(target string) *analyzer.WebsiteMetadata
	InspectTLS            func(target string) (analyzer.TLSInfo, error)
	TraceHTTPChain        func(target string) *analyzer.HTTPTraceResult
	InspectEmail          func(domain string) analyzer.EmailInfo
	InspectZone           func(domain string) *analyzer.DNSSECAndZoneAudit
	LookupVulnerabilities func(details []analyzer.TechDetail) ([]analyzer.Vulnerability, error)
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
	textScale    float32
	targetInput  string
	checkVulns   bool
	searchQuery  string
	activeTab    int

	scanning   bool
	statusText string

	scans            []storage.ScanSummary
	currentScan      *storage.ScanRecord
	currentPivots    []analyzer.PivotTarget
	childScans       []storage.ScanSummary
	scannedTargets   map[string]int64
	rawJSONReadOnly  string
	jsonSpansDark    []ui.Span
	jsonSpansLight   []ui.Span
	faviconCache     map[int64]cachedFavicon
	techFaviconCache map[string]cachedFavicon
	techFetching     map[string]bool

	mu sync.Mutex
}

func NewDesktopApp(store *storage.Store) *DesktopApp {
	app := &DesktopApp{
		store:            store,
		sidebarWidth:     330,
		textScale:        1.0,
		scannedTargets:   make(map[string]int64),
		faviconCache:     make(map[int64]cachedFavicon),
		techFaviconCache: make(map[string]cachedFavicon),
		techFetching:     make(map[string]bool),
		runner: ScanRunnerFunc{
			AnalyzeDomain:         analyzer.Analyze,
			AnalyzeIP:             analyzer.AnalyzeIP,
			ScanPorts:             analyzer.ScanPorts,
			RunPing:               analyzer.RunPing,
			RunTraceroute:         analyzer.RunTraceroute,
			EnumerateSubdomains:   analyzer.EnumerateSubdomains,
			InspectMetadata:       analyzer.InspectWebsiteMetadata,
			InspectTLS:            analyzer.InspectTLS,
			TraceHTTPChain:        analyzer.TraceHTTPChain,
			InspectEmail:          analyzer.InspectEmailDeliverability,
			InspectZone:           analyzer.InspectDNSSECAndZone,
			LookupVulnerabilities: analyzer.LookupVulnerabilities,
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

func (app *DesktopApp) fs(base float32) float32 {
	if app.textScale <= 0 {
		app.textScale = 1.0
	}
	return base * app.textScale
}

func (app *DesktopApp) IncreaseTextSize() {
	if app.textScale <= 0 {
		app.textScale = 1.0
	}
	app.textScale += 0.1
	if app.textScale > 2.0 {
		app.textScale = 2.0
	}
}

func (app *DesktopApp) DecreaseTextSize() {
	if app.textScale <= 0 {
		app.textScale = 1.0
	}
	app.textScale -= 0.1
	if app.textScale < 0.7 {
		app.textScale = 0.7
	}
}

func (app *DesktopApp) ResetTextSize() {
	app.textScale = 1.0
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
		if rec.IPInfo != nil {
			app.ensureTechFaviconsAsync(rec.IPInfo.Web.TechDetails)
		}
	} else {
		app.currentPivots = analyzer.ExtractDomainPivots(rec.DomainInfo)
		if rec.DomainInfo != nil {
			app.ensureTechFaviconsAsync(rec.DomainInfo.Web.TechDetails)
		}
	}
	if children, err := app.store.GetChildScans(id); err == nil {
		app.childScans = children
	}
}

func decodeFaviconEntry(raw []byte) cachedFavicon {
	var entry cachedFavicon
	entry.attempted = true
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return entry
	}
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
	return entry
}

// renderFavicon renders the decoded website favicon if present for a scan.
func (app *DesktopApp) renderFavicon(c *ui.Context, scanID int64, raw []byte, size float32) {
	if len(raw) == 0 {
		return
	}
	entry, ok := app.faviconCache[scanID]
	if !ok {
		entry = decodeFaviconEntry(raw)
		app.faviconCache[scanID] = entry
	}

	if entry.img != nil {
		ui.Image(c, entry.img).Size(size, size).Radius(3)
	} else if entry.svg != nil {
		ui.Icon(c, entry.svg).Size(size, size)
	}
}

// renderTechFavicon renders the decoded favicon for a detected technology.
func (app *DesktopApp) renderTechFavicon(c *ui.Context, techName string, raw []byte, size float32) {
	key := strings.ToLower(strings.TrimSpace(techName))
	if key == "" {
		return
	}
	entry, ok := app.techFaviconCache[key]
	if !ok && len(raw) > 0 {
		entry = decodeFaviconEntry(raw)
		app.techFaviconCache[key] = entry
	}
	if entry.img != nil {
		ui.Image(c, entry.img).Size(size, size).Radius(3)
	} else if entry.svg != nil {
		ui.Icon(c, entry.svg).Size(size, size)
	}
}

// ensureTechFaviconsAsync fetches favicons in the background for any TechDetail from older scans that didn't have Favicon bytes stored yet.
func (app *DesktopApp) ensureTechFaviconsAsync(details []analyzer.TechDetail) {
	for _, td := range details {
		key := strings.ToLower(strings.TrimSpace(td.Name))
		if key == "" {
			continue
		}
		if len(td.Favicon) > 0 {
			if _, ok := app.techFaviconCache[key]; !ok {
				app.techFaviconCache[key] = decodeFaviconEntry(td.Favicon)
			}
			continue
		}
		if _, ok := app.techFaviconCache[key]; ok || app.techFetching[key] || td.Website == "" {
			continue
		}
		app.techFetching[key] = true
		site := td.Website
		go func(k, website string) {
			raw := analyzer.FetchTechFavicon(website)
			app.runOnUI(func() {
				delete(app.techFetching, k)
				if len(raw) > 0 {
					app.techFaviconCache[k] = decodeFaviconEntry(raw)
				} else {
					app.techFaviconCache[k] = cachedFavicon{attempted: true}
				}
			})
		}(key, site)
	}
}

func (app *DesktopApp) renderTechStackList(c *ui.Context, t *ui.Theme, web analyzer.WebInfo) {
	details := web.TechDetails
	if len(details) == 0 && len(web.TechStack) > 0 {
		for _, name := range web.TechStack {
			site, icon := analyzer.LookupTechAppInfo(name)
			details = append(details, analyzer.TechDetail{
				Name:    name,
				Website: site,
				Icon:    icon,
			})
		}
	}

	if len(details) == 0 {
		app.renderKeyValue(c, t, "Detected Tech Stack", "None fingerprinted")
		return
	}

	ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		ui.Text(c, "Detected Tech Stack:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
		ui.Row(c).Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			for _, td := range details {
				tech := td
				label := tech.Name
				if tech.Version != "" {
					label = fmt.Sprintf("%s (%s)", tech.Name, tech.Version)
				}
				ui.Box(c).Key("tech:"+tech.Name).PaddingX(8).PaddingY(4).Radius(6).Background(t.Background).Border(1, t.Border).Children(func() {
					ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
						app.renderTechFavicon(c, tech.Name, tech.Favicon, 16)
						if tech.Website != "" {
							ui.Link(c, label+" ↗", tech.Website)
						} else {
							ui.Text(c, label).FontSize(app.fs(13))
						}
					})
				})
			}
		})
	})
}

// StartScan launches a domain or IP scan asynchronously and persists the result to SQLite.
// If parentID > 0 and a child scan for target already exists under parentID, it updates that child scan in place.
// If parentID == 0, it creates a new top-level scan.
func (app *DesktopApp) StartScan(rawTarget string, parentID int64, reason string) {
	app.startScanInternal(0, rawTarget, parentID, reason)
}

// RescanExisting updates an existing scan record (such as a child scan) in place.
func (app *DesktopApp) RescanExisting(scan *storage.ScanRecord) {
	if scan == nil {
		return
	}
	app.startScanInternal(scan.ID, scan.Target, scan.ParentScanID, scan.PivotReason)
}

func (app *DesktopApp) startScanInternal(updateScanID int64, rawTarget string, parentID int64, reason string) {
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
				if updateScanID > 0 {
					// Preserve any existing port scan results on this IP scan when re-scanning
					if existing, err := app.store.GetScan(updateScanID); err == nil && existing.IPInfo != nil && existing.IPInfo.PortScanned {
						info.PortScanned = true
						info.OpenPorts = existing.IPInfo.OpenPorts
					}
					saveErr = app.store.UpdateIPScan(updateScanID, info, reason, checkVulns)
					savedID = updateScanID
				} else {
					savedID, saveErr = app.store.SaveIPScan(info, parentID, reason, checkVulns)
				}
			}
		} else {
			info := app.runner.AnalyzeDomain(target, checkVulns)
			if app.store != nil {
				if updateScanID > 0 {
					saveErr = app.store.UpdateDomainScan(updateScanID, info, reason, checkVulns)
					savedID = updateScanID
				} else {
					savedID, saveErr = app.store.SaveDomainScan(info, parentID, reason, checkVulns)
				}
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Scan error: %v", saveErr)
				return
			}
			delete(app.faviconCache, savedID)
			app.statusText = fmt.Sprintf("Completed scan of %s", target)
			app.RefreshHistory()
			if savedID > 0 {
				app.SelectScan(savedID)
			}
		})
	}()
}

// StartPortScan runs a TCP port & service scan against the current IP scan and updates the record in SQLite.
func (app *DesktopApp) StartPortScan(scanID int64, info *analyzer.IPInfo, checkVulns bool) {
	if info == nil || info.IP == "" || app.scanning {
		return
	}
	targetIP := info.IP
	app.scanning = true
	app.statusText = fmt.Sprintf("Scanning TCP ports & services on %s...", targetIP)

	go func() {
		scanPortsFn := app.runner.ScanPorts
		if scanPortsFn == nil {
			scanPortsFn = analyzer.ScanPorts
		}
		ports := scanPortsFn(targetIP)

		info.Lock()
		info.PortScanned = true
		info.OpenPorts = ports
		info.Unlock()

		var saveErr error
		if app.store != nil {
			saveErr = app.store.UpdateIPScan(scanID, info, "", checkVulns)
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Port scan save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Port scan completed on %s (%d open ports)", targetIP, len(ports))
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartPing runs a Ping latency check against the currently selected domain or IP scan and persists the result.
func (app *DesktopApp) StartPing(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.scanning {
		return
	}
	rec := app.currentScan
	target := rec.Target
	app.scanning = true
	app.statusText = fmt.Sprintf("Pinging %s...", target)

	go func() {
		pingFn := app.runner.RunPing
		if pingFn == nil {
			pingFn = analyzer.RunPing
		}
		pingRes := pingFn(target)

		var saveErr error
		if app.store != nil {
			if rec.TargetType == analyzer.TargetTypeIP && rec.IPInfo != nil {
				rec.IPInfo.Lock()
				rec.IPInfo.Ping = pingRes
				rec.IPInfo.Unlock()
				saveErr = app.store.UpdateIPScan(scanID, rec.IPInfo, "", rec.CheckVulns)
			} else if rec.DomainInfo != nil {
				rec.DomainInfo.Lock()
				rec.DomainInfo.Ping = pingRes
				rec.DomainInfo.Unlock()
				saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Ping save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Ping completed for %s", target)
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartTraceroute runs a Traceroute network path check against the currently selected domain or IP scan and persists the result.
func (app *DesktopApp) StartTraceroute(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.scanning {
		return
	}
	rec := app.currentScan
	target := rec.Target
	app.scanning = true
	app.statusText = fmt.Sprintf("Running traceroute to %s...", target)

	go func() {
		traceFn := app.runner.RunTraceroute
		if traceFn == nil {
			traceFn = analyzer.RunTraceroute
		}
		traceRes := traceFn(target)

		var saveErr error
		if app.store != nil {
			if rec.TargetType == analyzer.TargetTypeIP && rec.IPInfo != nil {
				rec.IPInfo.Lock()
				rec.IPInfo.Traceroute = traceRes
				rec.IPInfo.Unlock()
				saveErr = app.store.UpdateIPScan(scanID, rec.IPInfo, "", rec.CheckVulns)
			} else if rec.DomainInfo != nil {
				rec.DomainInfo.Lock()
				rec.DomainInfo.Traceroute = traceRes
				rec.DomainInfo.Unlock()
				saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Traceroute save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Traceroute completed for %s (%d hops)", target, len(traceRes.Hops))
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartSubdomainEnum runs passive Certificate Transparency & DNS subdomain enumeration against the current domain scan.
func (app *DesktopApp) StartSubdomainEnum(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.currentScan.DomainInfo == nil || app.scanning {
		return
	}
	rec := app.currentScan
	domain := rec.DomainInfo.ApexDomain
	if domain == "" {
		domain = rec.DomainInfo.Domain
	}
	app.scanning = true
	app.statusText = fmt.Sprintf("Enumerating subdomains for %s (CT logs & DNS)...", domain)

	go func() {
		enumFn := app.runner.EnumerateSubdomains
		if enumFn == nil {
			enumFn = analyzer.EnumerateSubdomains
		}
		subRes := enumFn(domain)

		var saveErr error
		if app.store != nil && rec.DomainInfo != nil {
			rec.DomainInfo.Lock()
			rec.DomainInfo.Subdomains = subRes
			rec.DomainInfo.Unlock()
			saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Subdomain save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Discovered %d subdomains for %s (%d active)", subRes.TotalFound, domain, subRes.ActiveCount)
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartMetadataInspection fetches and parses website metadata, robots.txt, security.txt, and sitemap.xml for the current scan.
func (app *DesktopApp) StartMetadataInspection(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.scanning {
		return
	}
	rec := app.currentScan
	target := rec.Target
	app.scanning = true
	app.statusText = fmt.Sprintf("Inspecting metadata, robots.txt, security.txt & sitemap.xml for %s...", target)

	go func() {
		metaFn := app.runner.InspectMetadata
		if metaFn == nil {
			metaFn = analyzer.InspectWebsiteMetadata
		}
		metaRes := metaFn(target)

		var saveErr error
		if app.store != nil {
			if rec.TargetType == analyzer.TargetTypeIP && rec.IPInfo != nil {
				rec.IPInfo.Lock()
				rec.IPInfo.Metadata = metaRes
				rec.IPInfo.Unlock()
				saveErr = app.store.UpdateIPScan(scanID, rec.IPInfo, "", rec.CheckVulns)
			} else if rec.DomainInfo != nil {
				rec.DomainInfo.Lock()
				rec.DomainInfo.Metadata = metaRes
				rec.DomainInfo.Unlock()
				saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Metadata save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Completed metadata & well-known files inspection for %s", target)
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartTLSAudit runs a deep TLS & cipher suite audit against the currently selected domain or IP scan.
func (app *DesktopApp) StartTLSAudit(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.scanning {
		return
	}
	rec := app.currentScan
	target := rec.Target
	app.scanning = true
	app.statusText = fmt.Sprintf("Running deep TLS & cipher suite audit on %s...", target)

	go func() {
		tlsFn := app.runner.InspectTLS
		if tlsFn == nil {
			tlsFn = analyzer.InspectTLS
		}
		tlsRes, tlsErr := tlsFn(target)

		var saveErr error
		if tlsErr == nil && app.store != nil {
			if rec.TargetType == analyzer.TargetTypeIP && rec.IPInfo != nil {
				rec.IPInfo.Lock()
				rec.IPInfo.TLS = tlsRes
				rec.IPInfo.Unlock()
				saveErr = app.store.UpdateIPScan(scanID, rec.IPInfo, "", rec.CheckVulns)
			} else if rec.DomainInfo != nil {
				rec.DomainInfo.Lock()
				rec.DomainInfo.TLS = tlsRes
				rec.DomainInfo.Unlock()
				saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if tlsErr != nil {
				app.statusText = fmt.Sprintf("TLS audit error on %s: %v", target, tlsErr)
				return
			}
			if saveErr != nil {
				app.statusText = fmt.Sprintf("TLS save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Completed TLS audit for %s (Grade: %s)", target, tlsRes.Grade)
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartHTTPTrace traces the HTTP redirect chain and records performance timing waterfall metrics for the current scan.
func (app *DesktopApp) StartHTTPTrace(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.scanning {
		return
	}
	rec := app.currentScan
	target := rec.Target
	app.scanning = true
	app.statusText = fmt.Sprintf("Tracing HTTP redirects & waterfall timing for %s...", target)

	go func() {
		traceFn := app.runner.TraceHTTPChain
		if traceFn == nil {
			traceFn = analyzer.TraceHTTPChain
		}
		httpRes := traceFn(target)

		var saveErr error
		if app.store != nil {
			if rec.TargetType == analyzer.TargetTypeIP && rec.IPInfo != nil {
				rec.IPInfo.Lock()
				rec.IPInfo.HTTPTrace = httpRes
				rec.IPInfo.Unlock()
				saveErr = app.store.UpdateIPScan(scanID, rec.IPInfo, "", rec.CheckVulns)
			} else if rec.DomainInfo != nil {
				rec.DomainInfo.Lock()
				rec.DomainInfo.HTTPTrace = httpRes
				rec.DomainInfo.Unlock()
				saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("HTTP trace save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Completed HTTP trace for %s (%d redirects, %.1f ms total)", target, httpRes.RedirectCount, httpRes.TotalChainMs)
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartZoneAudit runs a DNSSEC chain-of-trust, SOA timer, IPv6 AAAA parity, and AXFR zone transfer audit for the current domain scan.
func (app *DesktopApp) StartZoneAudit(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.currentScan.DomainInfo == nil || app.scanning {
		return
	}
	rec := app.currentScan
	domain := rec.DomainInfo.Domain
	if domain == "" {
		domain = rec.Target
	}
	app.scanning = true
	app.statusText = fmt.Sprintf("Auditing DNSSEC, SOA, IPv6 AAAA & AXFR zone transfers for %s...", domain)

	go func() {
		zoneFn := app.runner.InspectZone
		if zoneFn == nil {
			zoneFn = analyzer.InspectDNSSECAndZone
		}
		zoneRes := zoneFn(domain)

		var saveErr error
		if app.store != nil && rec.DomainInfo != nil {
			rec.DomainInfo.Lock()
			rec.DomainInfo.ZoneAudit = zoneRes
			rec.DomainInfo.Unlock()
			saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Zone audit save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Completed DNSSEC & Zone audit for %s (%s)", domain, zoneRes.DNSSECStatus)
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartEmailDeepDive runs a deep-dive email deliverability & authentication audit (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI).
func (app *DesktopApp) StartEmailDeepDive(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.currentScan.DomainInfo == nil || app.scanning {
		return
	}
	rec := app.currentScan
	domain := rec.DomainInfo.ApexDomain
	if domain == "" {
		domain = rec.DomainInfo.Domain
	}
	app.scanning = true
	app.statusText = fmt.Sprintf("Auditing email deliverability & authentication (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI) for %s...", domain)

	go func() {
		emailFn := app.runner.InspectEmail
		if emailFn == nil {
			emailFn = analyzer.InspectEmailDeliverability
		}
		emailRes := emailFn(domain)

		var saveErr error
		if app.store != nil && rec.DomainInfo != nil {
			rec.DomainInfo.Lock()
			rec.DomainInfo.Email = emailRes
			rec.DomainInfo.Unlock()
			saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", rec.CheckVulns)
		}

		app.runOnUI(func() {
			app.scanning = false
			if saveErr != nil {
				app.statusText = fmt.Sprintf("Email audit save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Completed email deliverability audit for %s (%d DKIM selectors)", domain, len(emailRes.DKIMRecords))
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

// StartVulnerabilityCheck queries the NVD database for known CVEs affecting the detected web technology stack.
func (app *DesktopApp) StartVulnerabilityCheck(scanID int64) {
	if app.currentScan == nil || app.currentScan.ID != scanID || app.scanning {
		return
	}
	rec := app.currentScan
	target := rec.Target

	var details []analyzer.TechDetail
	if rec.TargetType == analyzer.TargetTypeIP && rec.IPInfo != nil {
		details = rec.IPInfo.Web.TechDetails
	} else if rec.DomainInfo != nil {
		details = rec.DomainInfo.Web.TechDetails
	}

	app.scanning = true
	app.statusText = fmt.Sprintf("Checking NVD CVE database for detected technologies on %s...", target)

	go func() {
		vulnFn := app.runner.LookupVulnerabilities
		if vulnFn == nil {
			vulnFn = analyzer.LookupVulnerabilities
		}
		vulns, vulnErr := vulnFn(details)

		var saveErr error
		if vulnErr == nil && app.store != nil {
			if rec.TargetType == analyzer.TargetTypeIP && rec.IPInfo != nil {
				rec.IPInfo.Lock()
				rec.IPInfo.VulnsChecked = true
				rec.IPInfo.Vulnerabilities = vulns
				rec.IPInfo.Unlock()
				saveErr = app.store.UpdateIPScan(scanID, rec.IPInfo, "", true)
			} else if rec.DomainInfo != nil {
				rec.DomainInfo.Lock()
				rec.DomainInfo.VulnsChecked = true
				rec.DomainInfo.Vulnerabilities = vulns
				rec.DomainInfo.Unlock()
				saveErr = app.store.UpdateDomainScan(scanID, rec.DomainInfo, "", true)
			}
		}

		app.runOnUI(func() {
			app.scanning = false
			if vulnErr != nil {
				app.statusText = fmt.Sprintf("CVE lookup error: %v", vulnErr)
				return
			}
			if saveErr != nil {
				app.statusText = fmt.Sprintf("CVE save error: %v", saveErr)
				return
			}
			app.statusText = fmt.Sprintf("Completed CVE check for %s (%d CVEs found)", target, len(vulns))
			app.RefreshHistory()
			app.SelectScan(scanID)
		})
	}()
}

func (app *DesktopApp) View(c *ui.Context) {
	if app.textScale <= 0 {
		app.textScale = 1.0
	}
	baseTheme := ui.LightTheme()
	if c.Theme().Dark {
		baseTheme = ui.DarkTheme()
	}
	defaultFontSize := baseTheme.FontSize
	if defaultFontSize <= 0 {
		defaultFontSize = 13
	}
	scaledTheme := *baseTheme
	scaledTheme.FontSize = defaultFontSize * app.textScale
	c.SetTheme(&scaledTheme)
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
		ui.Text(c, "Domain Analyzer").FontSize(app.fs(17)).Bold()

		inp := ui.TextInput(c, &app.targetInput).
			Placeholder("Enter domain (e.g. example.com) or IP (e.g. 93.184.216.34)...").
			Grow(1)
		if inp.Submitted() && strings.TrimSpace(app.targetInput) != "" && !app.scanning {
			target := app.targetInput
			app.StartScan(target, 0, "")
		}

		if ui.PrimaryButton(c, "Scan Target").Disabled(app.scanning || strings.TrimSpace(app.targetInput) == "").Clicked() {
			app.StartScan(app.targetInput, 0, "")
		}

		if app.scanning {
			ui.Spinner(c)
		}
		if app.statusText != "" {
			ui.Text(c, app.statusText).FontSize(app.fs(12)).TextColor(t.TextMuted)
		}

		// Text Size Controls (A- / % / A+)
		ui.Row(c).Gap(4).AlignItems(ui.Center).Children(func() {
			if ui.Button(c, "A-").Tooltip("Decrease text size").Disabled(app.textScale <= 0.71).Clicked() {
				app.DecreaseTextSize()
			}
			pctLabel := fmt.Sprintf("%d%%", int(app.textScale*100+0.5))
			if ui.Button(c, pctLabel).Tooltip("Reset text size to 100%").Clicked() {
				app.ResetTextSize()
			}
			if ui.Button(c, "A+").Tooltip("Increase text size").Disabled(app.textScale >= 1.99).Clicked() {
				app.IncreaseTextSize()
			}
		})
	})
}

func (app *DesktopApp) renderSidebar(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Fill().Padding(10).Gap(8).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			ui.Text(c, "Saved Scans").FontSize(app.fs(14)).Bold()
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
						FontSize(app.fs(12)).
						TextColor(t.TextMuted)
					return
				}

				for _, item := range app.scans {
					scanItem := item
					isSelected := app.currentScan != nil && app.currentScan.ID == scanItem.ID
					isChild := scanItem.Depth > 0

					cardBg := t.Surface
					borderCol := t.Border
					if isSelected {
						borderCol = t.Accent
					}

					indent := float32(scanItem.Depth) * 18
					ui.Row(c).Key(scanItem.ID).FillWidth().PaddingStart(indent).Gap(6).AlignItems(ui.Center).Children(func() {
						if isChild {
							connector := "├─"
							if scanItem.IsLastChild {
								connector = "└─"
							}
							ui.Text(c, connector).FontSize(app.fs(13)).Bold().TextColor(t.Accent)
						}

						card := ui.Box(c).
							Grow(1).
							Padding(10).
							Radius(6).
							Background(cardBg).
							Border(1, borderCol).
							Cursor(ui.CursorPointer)
						if isChild && !isSelected {
							card.BorderStartWidth(3)
						}

						card.Children(func() {
							ui.Column(c).FillWidth().Gap(4).Children(func() {
								ui.Row(c).FillWidth().Gap(6).AlignItems(ui.Center).Wrap().Children(func() {
									app.renderFavicon(c, scanItem.ID, scanItem.Favicon, 16)

									typeBadge := "DOMAIN"
									if scanItem.TargetType == analyzer.TargetTypeIP {
										typeBadge = "IP"
									}
									ui.Badge(c, typeBadge)
									ui.Text(c, scanItem.Target).Bold().FontSize(app.fs(13))

									if scanItem.ChildCount > 0 {
										ui.Spacer(c)
										ui.Badge(c, fmt.Sprintf("+%d child", scanItem.ChildCount))
									}
								})

								if scanItem.PivotReason != "" {
									ui.Text(c, fmt.Sprintf("Child scan via %s", scanItem.PivotReason)).
										FontSize(app.fs(11)).
										TextColor(t.Accent)
								}

								if scanItem.Summary != "" {
									ui.Text(c, scanItem.Summary).
										FontSize(app.fs(11)).
										TextColor(t.TextMuted).
										MaxLines(1).
										Ellipsis("...")
								}

								ui.Text(c, scanItem.CreatedAt.Local().Format("2006-01-02 15:04:05")).
									FontSize(app.fs(10)).
									TextColor(t.TextMuted)
							})
						})

						if card.Clicked() {
							app.SelectScan(scanItem.ID)
						}
					})
				}
			})
		})
	})
}

func (app *DesktopApp) renderDetailPane(c *ui.Context, t *ui.Theme) {
	if app.currentScan == nil {
		ui.Column(c).Fill().Center().Gap(10).Padding(24).Children(func() {
			ui.Text(c, "Select a scan from the left sidebar or start a new scan above.").
				FontSize(app.fs(15)).
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
			ui.Text(c, scan.Target).FontSize(app.fs(20)).Bold().Selectable()

			if scan.PivotReason != "" {
				ui.Badge(c, "via "+scan.PivotReason)
			}

			ui.Spacer(c)

			if ui.Button(c, "Re-scan ↻").Disabled(app.scanning).Clicked() {
				app.RescanExisting(scan)
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
		)).FontSize(app.fs(12)).TextColor(t.TextMuted)

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

	// Check if this target is already a direct child scan of the current scan
	var directChildID int64
	for _, ch := range app.childScans {
		if strings.EqualFold(strings.TrimSpace(ch.Target), lookupKey) {
			directChildID = ch.ID
			break
		}
	}
	existingScanID := directChildID
	if existingScanID == 0 {
		existingScanID = app.scannedTargets[lookupKey]
	}

	ui.Row(c).Key("pivot:" + reason + ":" + lookupKey).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		if label != "" {
			ui.Text(c, label+":").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(130)
		}
		ui.Text(c, cleanTarget).FontSize(app.fs(13)).Bold().Selectable()
		ui.Badge(c, reason)

		ui.Spacer(c)

		if existingScanID > 0 && (app.currentScan == nil || existingScanID != app.currentScan.ID) {
			viewLabel := "View Scan ✓"
			if directChildID > 0 {
				viewLabel = "View Child Scan ✓"
			}
			if ui.Button(c, viewLabel).Clicked() {
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
			ui.Text(c, title).FontSize(app.fs(14)).Bold()
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
		ui.Text(c, key+":").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
		ui.Text(c, val).FontSize(app.fs(13)).Selectable()
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
				ui.Text(c, "External WHOIS:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
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
			ui.Text(c, "Nameservers:").FontSize(app.fs(12)).TextColor(t.TextMuted)
			for _, ns := range info.DNS.Nameservers {
				app.renderPivotActionRow(c, t, scanID, "", ns, "Nameserver")
			}
		}

		if info.DNS.CAARecord != nil && len(info.DNS.CAARecord.RawRecords) > 0 {
			app.renderKeyValue(c, t, "CAA Records", strings.Join(info.DNS.CAARecord.RawRecords, "; "))
		}
	})

	// 2b. DNSSEC, SOA, IPv6 (AAAA) & Zone Transfer (AXFR) Audit
	app.renderZoneAuditCard(c, t, scanID, info)

	// 3. Passive Subdomain Enumeration (Certificate Transparency & DNS)
	app.renderSubdomainEnumerationCard(c, t, scanID, info)

	// 4. Ping & Traceroute Network Diagnostics
	app.renderPingAndTracerouteCards(c, t, scanID, info.Domain, info.Ping, info.Traceroute)

	// 4. WAF & Edge Protection (with CNAME chain drill-downs & OWASP Browser Challenges)
	app.renderSectionCard(c, t, "WAF & Edge Protection", func() {
		app.renderKeyValue(c, t, "WAF Summary", info.WAF.Summary)
		if info.WAF.BaselineStatus > 0 || info.WAF.ProbeStatus > 0 {
			app.renderKeyValue(c, t, "HTTP Probe Status", fmt.Sprintf("Baseline: HTTP %d → XSS Probe: HTTP %d", info.WAF.BaselineStatus, info.WAF.ProbeStatus))
		}

		// OWASP Passive/Challenge Links in Default Browser
		challenges := buildOWASPChallengeLinks(info.Domain, info.WAF)
		if len(challenges) > 0 {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, "OWASP Browser Challenges:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
				for _, ch := range challenges {
					ui.Link(c, ch.Label, ch.URL)
				}
			})
		}

		if len(info.WAF.CNAMEs) > 0 {
			ui.Text(c, "CNAME Chain (Drill-Down):").FontSize(app.fs(12)).TextColor(t.TextMuted)
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
						ui.Text(c, "Implementation: "+strings.Join(prov.Implementation, " | ")).FontSize(app.fs(12))
					}
					if len(prov.Evidence) > 0 {
						ui.Text(c, "Evidence: "+strings.Join(prov.Evidence, ", ")).FontSize(app.fs(11)).TextColor(t.TextMuted)
					}
				})
			})
		}

		for _, note := range info.WAF.OriginNotes {
			ui.Text(c, "Origin Note: "+note).FontSize(app.fs(12))
		}
	})

	// 4. Deep TLS & Cipher Suite Grading + Discovered SAN Domains
	app.renderTLSGradingCard(c, t, scanID, info.Domain, &info.TLS)

	// 5. Web Tech Stack & Security Headers (Deterministically ordered!) + On-Demand CVE Check
	app.renderSectionCard(c, t, "Web Technologies & Security Headers", func() {
		app.renderTechStackList(c, t, info.Web)
		app.renderWebCVESection(c, t, scanID, info.VulnsChecked, info.Vulnerabilities)

		orderedHeaders := sortedSecurityHeaders(info.Web.SecurityHeaders)
		if len(orderedHeaders) > 0 {
			ui.Text(c, "HTTP Security Headers:").FontSize(app.fs(12)).TextColor(t.TextMuted)
			for _, kv := range orderedHeaders {
				app.renderKeyValue(c, t, kv.Key, kv.Value)
			}
		}
	})

	// 6. HTTP Redirect Chain & Performance Timing Waterfall
	app.renderHTTPTraceCard(c, t, scanID, info.Domain, info.HTTPTrace)

	// 7. Website Metadata & Well-Known Files (robots.txt, security.txt, sitemap.xml)
	app.renderMetadataCard(c, t, scanID, info.Domain, info.Metadata)

	// 8. Email Deliverability & Authentication Deep-Dive (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI)
	app.renderEmailAuthCard(c, t, scanID, info)
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
				ui.Text(c, "External WHOIS:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
				ui.Link(c, "Open Full IP WHOIS in Browser ↗", "https://who.is/whois-ip/ip-address/"+url.PathEscape(info.IP))
			})
		}
	})

	// 2. Port & Service Discovery on IP
	app.renderSectionCard(c, t, "Port & Service Discovery", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			btnLabel := "Scan Host Ports"
			if info.PortScanned {
				btnLabel = "Re-scan Host Ports ↻"
			}
			if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
				checkVulns := false
				if app.currentScan != nil {
					checkVulns = app.currentScan.CheckVulns
				}
				app.StartPortScan(scanID, info, checkVulns)
			}

			if !info.PortScanned {
				ui.Text(c, "Click 'Scan Host Ports' to probe common TCP ports and identify operating services.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				ui.Badge(c, fmt.Sprintf("%d Open Ports Found", len(info.OpenPorts)))
			}
		})

		if info.PortScanned {
			if len(info.OpenPorts) == 0 {
				ui.Text(c, "No open TCP ports detected on common service ports.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				for _, p := range info.OpenPorts {
					portItem := p
					ui.Box(c).Key(fmt.Sprintf("port:%d", portItem.Port)).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
						ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Badge(c, fmt.Sprintf("TCP/%d", portItem.Port))
							ui.Text(c, portItem.Service).FontSize(app.fs(13)).Bold()
							ui.Badge(c, strings.ToUpper(portItem.State))
							if portItem.Banner != "" {
								ui.Text(c, "Banner: "+portItem.Banner).FontSize(app.fs(12)).TextColor(t.TextMuted).Selectable()
							}
						})
					})
				}
			}
		}
	})

	// 3. Ping & Traceroute Network Diagnostics
	app.renderPingAndTracerouteCards(c, t, scanID, info.IP, info.Ping, info.Traceroute)

	// 4. Reverse DNS (PTR) Hostnames
	app.renderSectionCard(c, t, "Reverse DNS (PTR Hostnames)", func() {
		if len(info.PTRRecords) == 0 {
			ui.Text(c, "No PTR records found for this IP address.").FontSize(app.fs(12)).TextColor(t.TextMuted)
			return
		}
		for _, ptr := range info.PTRRecords {
			app.renderPivotActionRow(c, t, scanID, "PTR Hostname", ptr, "PTR Record")
		}
	})

	// 4. Deep TLS & Cipher Suite Grading (:443) & Certificate Domains
	app.renderTLSGradingCard(c, t, scanID, info.IP, &info.TLS)

	// 4. Direct HTTP / WAF / Tech Stack on IP
	app.renderSectionCard(c, t, "Direct HTTP, WAF & Tech Fingerprinting", func() {
		app.renderKeyValue(c, t, "WAF Summary", info.WAF.Summary)

		challenges := buildOWASPChallengeLinks(info.IP, info.WAF)
		if len(challenges) > 0 {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, "OWASP Browser Challenges:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
				for _, ch := range challenges {
					ui.Link(c, ch.Label, ch.URL)
				}
			})
		}

		app.renderTechStackList(c, t, info.Web)
		app.renderWebCVESection(c, t, scanID, info.VulnsChecked, info.Vulnerabilities)

		orderedHeaders := sortedSecurityHeaders(info.Web.SecurityHeaders)
		for _, kv := range orderedHeaders {
			app.renderKeyValue(c, t, kv.Key, kv.Value)
		}
	})

	// 5. HTTP Redirect Chain & Performance Timing Waterfall
	app.renderHTTPTraceCard(c, t, scanID, info.IP, info.HTTPTrace)

	// 6. Website Metadata & Well-Known Files (robots.txt, security.txt, sitemap.xml)
	app.renderMetadataCard(c, t, scanID, info.IP, info.Metadata)
}

func (app *DesktopApp) renderHTTPTraceCard(c *ui.Context, t *ui.Theme, scanID int64, target string, trace *analyzer.HTTPTraceResult) {
	app.renderSectionCard(c, t, "HTTP Redirect Chain & Performance Timing Waterfall", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			btnLabel := "Trace Redirects & Timing"
			if trace != nil {
				btnLabel = "Re-trace HTTP ↻"
			}
			if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
				app.StartHTTPTrace(scanID)
			}

			if trace == nil {
				ui.Text(c, "Click 'Trace Redirects & Timing' to inspect the HTTP → HTTPS redirect chain and phase-by-phase latency waterfall.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				ui.Badge(c, fmt.Sprintf("%d Redirects", trace.RedirectCount))
				if trace.FinalStatus > 0 {
					ui.Badge(c, fmt.Sprintf("Final: HTTP %d", trace.FinalStatus))
				}
				if trace.UpgradedHTTPS {
					ui.Badge(c, "HTTP → HTTPS Upgraded")
				}
				ui.Badge(c, fmt.Sprintf("Total Chain: %.1f ms", trace.TotalChainMs))
			}
		})

		if trace == nil {
			return
		}

		if trace.Error != "" && len(trace.Hops) == 0 {
			ui.Text(c, "HTTP trace error: "+trace.Error).FontSize(app.fs(12)).TextColor(t.Danger)
			return
		}

		// 1. Performance Timing Waterfall Breakdown
		wf := trace.Waterfall
		if wf.StatusCode > 0 {
			ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
				ui.Column(c).FillWidth().Gap(6).Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
						ui.Text(c, "Performance Timing Waterfall").FontSize(app.fs(13)).Bold()
						if wf.Protocol != "" {
							ui.Badge(c, wf.Protocol)
						}
						ui.Badge(c, fmt.Sprintf("HTTP %d", wf.StatusCode))
						ui.Spacer(c)
						if wf.URL != "" {
							ui.Link(c, wf.URL+" ↗", wf.URL)
						}
					})

					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
						ui.Badge(c, fmt.Sprintf("DNS Lookup: %.2f ms", wf.DNSMs))
						ui.Badge(c, fmt.Sprintf("TCP Connect: %.2f ms", wf.TCPConnectMs))
						ui.Badge(c, fmt.Sprintf("TLS Handshake: %.2f ms", wf.TLSHandshakeMs))
						ui.Badge(c, fmt.Sprintf("TTFB: %.2f ms", wf.TTFBMs))
						ui.Badge(c, fmt.Sprintf("Transfer: %.2f ms", wf.ContentTransferMs))
						ui.Badge(c, fmt.Sprintf("Total: %.2f ms", wf.TotalMs))
					})
				})
			})
		}

		// 2. Step-by-Step Redirect Chain
		if len(trace.Hops) > 0 {
			ui.Text(c, fmt.Sprintf("Redirect Chain (%d Hop%s):", len(trace.Hops), func() string {
				if len(trace.Hops) == 1 {
					return ""
				}
				return "s"
			}())).FontSize(app.fs(12)).TextColor(t.TextMuted)

			for _, h := range trace.Hops {
				hop := h
				ui.Box(c).Key(fmt.Sprintf("httphop:%d:%s", hop.Step, hop.URL)).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
					ui.Column(c).FillWidth().Gap(4).Children(func() {
						ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Badge(c, fmt.Sprintf("Hop #%d", hop.Step))
							ui.Badge(c, hop.Status)
							if hop.Protocol != "" {
								ui.Badge(c, hop.Protocol)
							}
							ui.Badge(c, fmt.Sprintf("%.2f ms", hop.TotalMs))
							if hop.Server != "" {
								ui.Badge(c, "Server: "+hop.Server)
							}
							ui.Spacer(c)
							ui.Link(c, hop.URL+" ↗", hop.URL)
						})
						if hop.Location != "" {
							ui.Text(c, "  ↳ Redirects to Location: "+hop.Location).FontSize(app.fs(12)).TextColor(t.TextMuted).Selectable()
						}
					})
				})
			}
		}

		// 3. Discovered External / Subdomain Redirect Hosts
		if len(trace.DiscoveredHosts) > 0 {
			ui.Text(c, "Redirected Hosts (Drill-Down):").FontSize(app.fs(12)).TextColor(t.TextMuted)
			for _, h := range trace.DiscoveredHosts {
				app.renderPivotActionRow(c, t, scanID, "Redirect Host", h, "HTTP Redirect")
			}
		}
	})
}

func (app *DesktopApp) renderTLSGradingCard(c *ui.Context, t *ui.Theme, scanID int64, target string, tlsInfo *analyzer.TLSInfo) {
	app.renderSectionCard(c, t, "Deep TLS, Cipher Suite Grading & Certificate SANs", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			btnLabel := "Audit TLS & Ciphers"
			if tlsInfo != nil && tlsInfo.Grade != "" {
				btnLabel = "Re-audit TLS ↻"
			}
			if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
				app.StartTLSAudit(scanID)
			}

			if tlsInfo == nil || !tlsInfo.HasTLS {
				ui.Text(c, "No TLS service detected on port 443.").FontSize(app.fs(12)).TextColor(t.TextMuted)
			} else {
				if tlsInfo.Grade != "" {
					ui.Badge(c, "Grade: "+tlsInfo.Grade)
				}
				if tlsInfo.NegotiatedVersion != "" {
					ui.Badge(c, tlsInfo.NegotiatedVersion)
				}
				if tlsInfo.ChainValid {
					ui.Badge(c, "Chain Trusted")
				} else if tlsInfo.Grade != "" {
					ui.Badge(c, "Chain Untrusted")
				}
				if tlsInfo.TLSExpiry != "" {
					if tlsInfo.DaysRemaining < 0 {
						ui.Badge(c, fmt.Sprintf("EXPIRED (%dd ago)", -tlsInfo.DaysRemaining))
					} else if tlsInfo.DaysRemaining > 0 || tlsInfo.Grade != "" {
						ui.Badge(c, fmt.Sprintf("%d Days Remaining", tlsInfo.DaysRemaining))
					}
				}
				if tlsInfo.HasCertTransparency {
					ui.Badge(c, "CT SCT: Present")
				}
				if tlsInfo.OCSPStapled {
					ui.Badge(c, "OCSP Stapled")
				}
			}
		})

		if tlsInfo == nil || !tlsInfo.HasTLS {
			return
		}

		if tlsInfo.GradeSummary != "" {
			app.renderKeyValue(c, t, "TLS Grade Summary", fmt.Sprintf("[%s] %s", tlsInfo.Grade, tlsInfo.GradeSummary))
		}

		if len(tlsInfo.GradeWarnings) > 0 {
			ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Danger).Children(func() {
				ui.Column(c).FillWidth().Gap(4).Children(func() {
					ui.Text(c, "TLS Findings & Warnings:").FontSize(app.fs(12)).Bold().TextColor(t.Danger)
					for _, w := range tlsInfo.GradeWarnings {
						ui.Text(c, "• "+w).FontSize(app.fs(12)).TextColor(t.Danger)
					}
				})
			})
		}

		if len(tlsInfo.SupportedVersions) > 0 {
			app.renderKeyValue(c, t, "Supported Protocols", strings.Join(tlsInfo.SupportedVersions, ", "))
		}
		if tlsInfo.CipherSuite != "" {
			cipherLine := tlsInfo.CipherSuite
			if tlsInfo.ALPNProtocol != "" {
				cipherLine += fmt.Sprintf(" (ALPN: %s)", tlsInfo.ALPNProtocol)
			}
			app.renderKeyValue(c, t, "Negotiated Cipher", cipherLine)
		}
		if tlsInfo.KeyAlgorithm != "" {
			keyLine := tlsInfo.KeyAlgorithm
			if tlsInfo.SignatureAlgorithm != "" {
				keyLine += fmt.Sprintf(" — Signature: %s", tlsInfo.SignatureAlgorithm)
			}
			app.renderKeyValue(c, t, "Public Key & Sig", keyLine)
		}

		if tlsInfo.SubjectCN != "" {
			app.renderKeyValue(c, t, "Certificate Subject", tlsInfo.SubjectCN)
		}
		app.renderKeyValue(c, t, "TLS Issuer", tlsInfo.TLSIssuer)
		if tlsInfo.ValidFrom != "" {
			app.renderKeyValue(c, t, "Validity Window", fmt.Sprintf("%s → %s", tlsInfo.ValidFrom, tlsInfo.TLSExpiry))
		} else {
			app.renderKeyValue(c, t, "TLS Expiry", tlsInfo.TLSExpiry)
		}

		if len(tlsInfo.ChainSummary) > 0 {
			ui.Text(c, fmt.Sprintf("Certificate Chain (%d):", len(tlsInfo.ChainSummary))).FontSize(app.fs(12)).TextColor(t.TextMuted)
			for _, certLine := range tlsInfo.ChainSummary {
				ui.Text(c, "  "+certLine).FontSize(app.fs(12)).Selectable()
			}
		}

		if len(tlsInfo.SANDomains) > 0 {
			ui.Text(c, fmt.Sprintf("Subject Alternative Names (%d):", len(tlsInfo.SANDomains))).
				FontSize(app.fs(12)).
				TextColor(t.TextMuted)
			for _, san := range tlsInfo.SANDomains {
				app.renderPivotActionRow(c, t, scanID, "", san, "TLS SAN")
			}
		}
	})
}

func (app *DesktopApp) renderMetadataCard(c *ui.Context, t *ui.Theme, scanID int64, target string, meta *analyzer.WebsiteMetadata) {
	app.renderSectionCard(c, t, "Website Metadata & Well-Known Files (robots.txt, security.txt, sitemap.xml)", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			btnLabel := "Inspect Metadata"
			if meta != nil {
				btnLabel = "Re-inspect Metadata ↻"
			}
			if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
				app.StartMetadataInspection(scanID)
			}

			if meta == nil {
				ui.Text(c, "Click 'Inspect Metadata' to fetch and parse HTML metadata, /robots.txt, /.well-known/security.txt, and /sitemap.xml.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				if meta.RobotsTxt.Found {
					ui.Badge(c, fmt.Sprintf("robots.txt: %d Disallow", len(meta.RobotsTxt.DisallowedPaths)))
				} else {
					ui.Badge(c, "robots.txt: Not Found")
				}
				if meta.SecurityTxt.Found {
					ui.Badge(c, "security.txt: Present")
				} else {
					ui.Badge(c, "security.txt: Missing")
				}
				if meta.Sitemap.Found {
					ui.Badge(c, fmt.Sprintf("sitemap.xml: %d URLs", meta.Sitemap.URLCount))
				} else {
					ui.Badge(c, "sitemap.xml: Not Found")
				}
			}
		})

		if meta == nil {
			return
		}

		// 1. HTML Page Metadata
		if meta.PageTitle != "" {
			app.renderKeyValue(c, t, "Page Title", meta.PageTitle)
		}
		if meta.MetaDescription != "" {
			app.renderKeyValue(c, t, "Meta Description", meta.MetaDescription)
		}
		if meta.MetaGenerator != "" {
			app.renderKeyValue(c, t, "Meta Generator", meta.MetaGenerator)
		}
		if meta.CanonicalURL != "" {
			app.renderKeyValue(c, t, "Canonical URL", meta.CanonicalURL)
		}

		// 2. robots.txt Subsection
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "robots.txt").FontSize(app.fs(13)).Bold()
					if meta.RobotsTxt.Found {
						ui.Badge(c, "FOUND")
					} else {
						ui.Badge(c, "NOT FOUND")
					}
					ui.Spacer(c)
					robotsURL := meta.RobotsTxt.URL
					if robotsURL == "" && target != "" {
						robotsURL = "https://" + target + "/robots.txt"
					}
					if robotsURL != "" {
						ui.Link(c, "Open robots.txt ↗", robotsURL)
					}
				})

				if meta.RobotsTxt.Found {
					if len(meta.RobotsTxt.UserAgents) > 0 {
						app.renderKeyValue(c, t, "User-Agents", strings.Join(meta.RobotsTxt.UserAgents, ", "))
					}
					if len(meta.RobotsTxt.DisallowedPaths) > 0 {
						ui.Row(c).FillWidth().Gap(6).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Text(c, "Disallowed Paths:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
							for _, p := range meta.RobotsTxt.DisallowedPaths {
								ui.Badge(c, p)
							}
						})
					}
					if len(meta.RobotsTxt.AllowedPaths) > 0 {
						app.renderKeyValue(c, t, "Allowed Paths", strings.Join(meta.RobotsTxt.AllowedPaths, ", "))
					}
					if len(meta.RobotsTxt.Sitemaps) > 0 {
						ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Text(c, "Declared Sitemaps:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
							for _, sm := range meta.RobotsTxt.Sitemaps {
								ui.Link(c, sm+" ↗", sm)
							}
						})
					}
				} else {
					ui.Text(c, "No valid /robots.txt file detected.").FontSize(app.fs(12)).TextColor(t.TextMuted)
				}
			})
		})

		// 3. security.txt (RFC 9116) Subsection
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "security.txt (RFC 9116)").FontSize(app.fs(13)).Bold()
					if meta.SecurityTxt.Found {
						ui.Badge(c, "PRESENT")
					} else {
						ui.Badge(c, "MISSING")
					}
					ui.Spacer(c)
					secURL := meta.SecurityTxt.URL
					if secURL == "" && target != "" {
						secURL = "https://" + target + "/.well-known/security.txt"
					}
					if secURL != "" {
						ui.Link(c, "Open security.txt ↗", secURL)
					}
				})

				if meta.SecurityTxt.Found {
					if len(meta.SecurityTxt.Contacts) > 0 {
						app.renderKeyValue(c, t, "Security Contacts", strings.Join(meta.SecurityTxt.Contacts, ", "))
					}
					if meta.SecurityTxt.Expires != "" {
						app.renderKeyValue(c, t, "Expires", meta.SecurityTxt.Expires)
					}
					if len(meta.SecurityTxt.Policy) > 0 {
						ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Text(c, "Disclosure Policy:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
							for _, pol := range meta.SecurityTxt.Policy {
								if strings.HasPrefix(pol, "http://") || strings.HasPrefix(pol, "https://") {
									ui.Link(c, pol+" ↗", pol)
								} else {
									ui.Text(c, pol).FontSize(app.fs(12)).Selectable()
								}
							}
						})
					}
					if len(meta.SecurityTxt.Encryption) > 0 {
						app.renderKeyValue(c, t, "Encryption (PGP)", strings.Join(meta.SecurityTxt.Encryption, ", "))
					}
					if len(meta.SecurityTxt.Acknowledgments) > 0 {
						app.renderKeyValue(c, t, "Acknowledgments", strings.Join(meta.SecurityTxt.Acknowledgments, ", "))
					}
				} else {
					ui.Text(c, "No RFC 9116 security.txt found at /.well-known/security.txt or /security.txt.").
						FontSize(app.fs(12)).
						TextColor(t.TextMuted)
				}
			})
		})

		// 4. sitemap.xml Subsection
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "sitemap.xml").FontSize(app.fs(13)).Bold()
					if meta.Sitemap.Found {
						if meta.Sitemap.IsIndex {
							ui.Badge(c, "SITEMAP INDEX")
						} else {
							ui.Badge(c, "URL SET")
						}
						ui.Badge(c, fmt.Sprintf("%d Entries", meta.Sitemap.URLCount))
					} else {
						ui.Badge(c, "NOT FOUND")
					}
					ui.Spacer(c)
					smURL := meta.Sitemap.URL
					if smURL == "" && target != "" {
						smURL = "https://" + target + "/sitemap.xml"
					}
					if smURL != "" {
						ui.Link(c, "Open sitemap.xml ↗", smURL)
					}
				})

				if meta.Sitemap.Found {
					if len(meta.Sitemap.SampleURLs) > 0 {
						ui.Text(c, fmt.Sprintf("Sample Sitemap Entries (%d of %d):", len(meta.Sitemap.SampleURLs), meta.Sitemap.URLCount)).
							FontSize(app.fs(12)).
							TextColor(t.TextMuted)
						for _, loc := range meta.Sitemap.SampleURLs {
							locURL := loc
							ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
								ui.Link(c, locURL+" ↗", locURL)
							})
						}
					}
					if len(meta.Sitemap.DiscoveredHosts) > 0 {
						ui.Text(c, "Hosts Referenced in Sitemap:").FontSize(app.fs(12)).TextColor(t.TextMuted)
						for _, h := range meta.Sitemap.DiscoveredHosts {
							app.renderPivotActionRow(c, t, scanID, "Sitemap Host", h, "Sitemap Host")
						}
					}
				} else {
					ui.Text(c, "No valid XML sitemap detected.").FontSize(app.fs(12)).TextColor(t.TextMuted)
				}
			})
		})
	})
}

func (app *DesktopApp) renderSubdomainEnumerationCard(c *ui.Context, t *ui.Theme, scanID int64, info *analyzer.DomainInfo) {
	apex := info.ApexDomain
	if apex == "" {
		apex = info.Domain
	}

	app.renderSectionCard(c, t, "Passive Subdomain Enumeration (CT Logs & DNS)", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			btnLabel := "Enumerate Subdomains"
			if info.Subdomains != nil {
				btnLabel = "Re-enumerate Subdomains ↻"
			}
			if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
				app.StartSubdomainEnum(scanID)
			}

			if info.Subdomains == nil {
				ui.Text(c, fmt.Sprintf("Click 'Enumerate Subdomains' to discover subdomains of %s via Certificate Transparency (crt.sh) & DNS.", apex)).
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				ui.Badge(c, fmt.Sprintf("%d Discovered", info.Subdomains.TotalFound))
				ui.Badge(c, fmt.Sprintf("%d Active (DNS)", info.Subdomains.ActiveCount))
				if len(info.Subdomains.SourcesUsed) > 0 {
					ui.Badge(c, "Sources: "+strings.Join(info.Subdomains.SourcesUsed, ", "))
				}
			}

			ui.Spacer(c)
			if apex != "" {
				ui.Link(c, "Open crt.sh ↗", "https://crt.sh/?q=%25."+url.QueryEscape(apex))
			}
		})

		if info.Subdomains != nil {
			if info.Subdomains.Error != "" && len(info.Subdomains.Subdomains) == 0 {
				ui.Text(c, "Subdomain lookup note: "+info.Subdomains.Error).FontSize(app.fs(12)).TextColor(t.Danger)
				return
			}
			if len(info.Subdomains.Subdomains) == 0 {
				ui.Text(c, "No additional subdomains discovered.").FontSize(app.fs(12)).TextColor(t.TextMuted)
				return
			}

			for _, s := range info.Subdomains.Subdomains {
				subItem := s
				ui.Box(c).Key("sub:"+subItem.Subdomain).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
						ui.Text(c, subItem.Subdomain).FontSize(app.fs(13)).Bold().Selectable()

						if subItem.Active {
							ui.Badge(c, "ACTIVE")
						} else {
							ui.Badge(c, "HISTORICAL (CT)")
						}

						if len(subItem.Sources) > 0 {
							ui.Badge(c, strings.Join(subItem.Sources, "+"))
						}

						if len(subItem.IPAddresses) > 0 {
							ui.Text(c, "IP: "+strings.Join(subItem.IPAddresses, ", ")).
								FontSize(app.fs(12)).
								TextColor(t.TextMuted).
								Selectable()
						}
						if subItem.CNAME != "" {
							ui.Text(c, "CNAME: "+subItem.CNAME).
								FontSize(app.fs(12)).
								TextColor(t.TextMuted).
								Selectable()
						}

						ui.Spacer(c)

						if !strings.EqualFold(subItem.Subdomain, info.Domain) {
							lookupKey := strings.ToLower(strings.TrimSpace(subItem.Subdomain))
							if existingID, exists := app.scannedTargets[lookupKey]; exists && existingID != scanID {
								if ui.Button(c, "Open Scan →").Clicked() {
									app.SelectScan(existingID)
									app.activeTab = 0
								}
								if ui.Button(c, "Re-scan ↻").Disabled(app.scanning).Clicked() {
									app.StartScan(subItem.Subdomain, scanID, "Subdomain")
								}
							} else {
								if ui.PrimaryButton(c, "Scan Subdomain ↗").Disabled(app.scanning).Clicked() {
									app.StartScan(subItem.Subdomain, scanID, "Subdomain")
								}
							}
						}
					})
				})
			}
		}
	})
}

func (app *DesktopApp) renderPingAndTracerouteCards(c *ui.Context, t *ui.Theme, scanID int64, target string, ping *analyzer.PingResult, trace *analyzer.TracerouteResult) {
	// Ping Section
	app.renderSectionCard(c, t, "Ping & Latency Check", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			pingBtnLabel := "Run Ping"
			if ping != nil {
				pingBtnLabel = "Re-run Ping ↻"
			}
			if ui.PrimaryButton(c, pingBtnLabel).Disabled(app.scanning).Clicked() {
				app.StartPing(scanID)
			}

			if ping == nil {
				ui.Text(c, "Click 'Run Ping' to measure packet loss and round-trip latency.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				statusLabel := "Unreachable"
				if ping.Reachable {
					statusLabel = "Reachable"
				}
				ui.Badge(c, statusLabel)
				if ping.Method != "" {
					ui.Badge(c, ping.Method)
				}
				ui.Badge(c, fmt.Sprintf("%.0f%% Loss (%d/%d)", ping.LossPercent, ping.PacketsRecv, ping.PacketsSent))
			}
		})

		if ping != nil {
			if ping.ResolvedIP != "" && ping.ResolvedIP != target {
				app.renderKeyValue(c, t, "Resolved IP", ping.ResolvedIP)
			}
			if ping.Reachable {
				app.renderKeyValue(c, t, "RTT (Min / Avg / Max)", fmt.Sprintf("%s / %s / %s", ping.MinRTT, ping.AvgRTT, ping.MaxRTT))
			}
			if len(ping.Probes) > 0 {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "Probes:").FontSize(app.fs(12)).TextColor(t.TextMuted).MinWidth(140)
					for _, pr := range ping.Probes {
						probe := pr
						label := fmt.Sprintf("#%d: %s", probe.Seq, probe.Detail)
						ui.Badge(c, label)
					}
				})
			}
		}
	})

	// Traceroute Section
	app.renderSectionCard(c, t, "Traceroute & Network Path", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			traceBtnLabel := "Run Traceroute"
			if trace != nil {
				traceBtnLabel = "Re-run Traceroute ↻"
			}
			if ui.PrimaryButton(c, traceBtnLabel).Disabled(app.scanning).Clicked() {
				app.StartTraceroute(scanID)
			}

			if trace == nil {
				ui.Text(c, "Click 'Run Traceroute' to map network hops and intermediate routers to this target.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				if trace.Method != "" {
					ui.Badge(c, trace.Method)
				}
				ui.Badge(c, fmt.Sprintf("%d Hops", len(trace.Hops)))
				if trace.Completed {
					ui.Badge(c, "Reached Target")
				}
			}
		})

		if trace != nil {
			if trace.Error != "" {
				ui.Text(c, "Traceroute error: "+trace.Error).FontSize(app.fs(12)).TextColor(t.Danger)
			} else if len(trace.Hops) == 0 {
				ui.Text(c, "No hops returned.").FontSize(app.fs(12)).TextColor(t.TextMuted)
			} else {
				for _, h := range trace.Hops {
					hop := h
					ui.Box(c).Key(fmt.Sprintf("hop:%d:%s", hop.Hop, hop.IP)).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
						ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Badge(c, fmt.Sprintf("#%d", hop.Hop))
							if hop.Timeout || (hop.IP == "" && hop.Host == "") {
								ui.Text(c, "* * * (Request Timed Out)").FontSize(app.fs(12)).TextColor(t.TextMuted)
							} else {
								if hop.IP != "" {
									ui.Text(c, hop.IP).FontSize(app.fs(13)).Bold().Selectable()
								}
								if hop.Host != "" && hop.Host != hop.IP {
									ui.Text(c, fmt.Sprintf("(%s)", hop.Host)).FontSize(app.fs(12)).TextColor(t.TextMuted).Selectable()
								}
								if hop.RTT != "" {
									ui.Badge(c, hop.RTT)
								}
								ui.Spacer(c)
								if hop.IP != "" && hop.IP != target && analyzer.IsPublicRoutableIP(hop.IP) {
									if ui.Button(c, "Scan Hop IP ↗").Disabled(app.scanning).Clicked() {
										app.StartScan(hop.IP, scanID, fmt.Sprintf("Traceroute Hop #%d", hop.Hop))
									}
								}
							}
						})
					})
				}
			}
		}
	})
}

func (app *DesktopApp) renderZoneAuditCard(c *ui.Context, t *ui.Theme, scanID int64, info *analyzer.DomainInfo) {
	za := info.ZoneAudit

	app.renderSectionCard(c, t, "DNSSEC, SOA, IPv6 (AAAA) & Zone Transfer (AXFR) Audit", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			btnLabel := "Audit DNSSEC & Zone"
			if za != nil && za.Audited {
				btnLabel = "Re-audit Zone ↻"
			}
			if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
				app.StartZoneAudit(scanID)
			}

			if za == nil {
				ui.Text(c, "Click 'Audit DNSSEC & Zone' to verify DNSSEC chain of trust (DS/DNSKEY/RRSIG), SOA timers, IPv6 AAAA parity, and open AXFR zone transfers.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			} else {
				ui.Badge(c, "DNSSEC: "+za.DNSSECStatus)
				if za.HasIPv6 {
					ui.Badge(c, fmt.Sprintf("IPv6 (AAAA): %d IPs", len(za.IPv6Addresses)+len(za.WWWIPv6Addresses)))
				} else {
					ui.Badge(c, "IPv6 (AAAA): None")
				}
				if za.AXFRChecked {
					if za.AXFRVulnerable {
						ui.Badge(c, "AXFR: VULNERABLE")
					} else {
						ui.Badge(c, "AXFR: Refused (Secure)")
					}
				}
				if za.SOA != nil && za.SOA.Serial > 0 {
					ui.Badge(c, fmt.Sprintf("SOA Serial: %d", za.SOA.Serial))
				}
			}
		})

		if za == nil {
			return
		}

		// 1. IPv6 (AAAA) Parity
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "IPv6 (AAAA) Dual-Stack Parity").FontSize(app.fs(13)).Bold()
					if za.HasIPv6 {
						ui.Badge(c, "DUAL-STACK (IPv4 + IPv6)")
					} else {
						ui.Badge(c, "IPv4 ONLY")
					}
				})

				if !za.HasIPv6 {
					ui.Text(c, "No AAAA (IPv6) records resolved for this host.").FontSize(app.fs(12)).TextColor(t.TextMuted)
				} else {
					for _, ip6 := range za.IPv6Addresses {
						app.renderPivotActionRow(c, t, scanID, "AAAA Record IPv6", ip6, "AAAA Record")
					}
					for _, ip6 := range za.WWWIPv6Addresses {
						app.renderPivotActionRow(c, t, scanID, "WWW AAAA IPv6", ip6, "WWW AAAA Record")
					}
				}
			})
		})

		// 2. DNSSEC Chain of Trust (DS, DNSKEY, RRSIG)
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "DNSSEC Chain of Trust (DS, DNSKEY, RRSIG)").FontSize(app.fs(13)).Bold()
					ui.Badge(c, za.DNSSECStatus)
					if za.DNSSECValidated {
						ui.Badge(c, "AD Bit Validated")
					}
					if za.RRSIGCount > 0 {
						ui.Badge(c, fmt.Sprintf("%d RRSIGs", za.RRSIGCount))
					}
				})

				if za.DNSSECSummary != "" {
					app.renderKeyValue(c, t, "DNSSEC Summary", za.DNSSECSummary)
				}

				if len(za.DSRecords) > 0 {
					ui.Text(c, fmt.Sprintf("Parent Zone DS Records (%d):", len(za.DSRecords))).FontSize(app.fs(12)).TextColor(t.TextMuted)
					for _, d := range za.DSRecords {
						ds := d
						ui.Row(c).Key(fmt.Sprintf("ds:%d:%s", ds.KeyTag, ds.Digest)).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Badge(c, fmt.Sprintf("KeyTag: %d", ds.KeyTag))
							ui.Badge(c, ds.AlgoName)
							ui.Badge(c, ds.DigestName)
							ui.Text(c, ds.Digest).FontSize(app.fs(11)).TextColor(t.TextMuted).Selectable()
						})
					}
				}

				if len(za.DNSKEYRecords) > 0 {
					ui.Text(c, fmt.Sprintf("Zone DNSKEY Records (%d):", len(za.DNSKEYRecords))).FontSize(app.fs(12)).TextColor(t.TextMuted)
					for _, k := range za.DNSKEYRecords {
						keyRec := k
						ui.Row(c).Key(fmt.Sprintf("dnskey:%d:%d", keyRec.KeyTag, keyRec.Flags)).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Badge(c, keyRec.Role)
							ui.Badge(c, fmt.Sprintf("KeyTag: %d", keyRec.KeyTag))
							ui.Badge(c, keyRec.AlgoName)
							if keyRec.PublicKey != "" {
								ui.Text(c, keyRec.PublicKey).FontSize(app.fs(11)).TextColor(t.TextMuted).Selectable()
							}
						})
					}
				}
			})
		})

		// 3. Start of Authority (SOA) Record & Zone Timers
		if za.SOA != nil {
			ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
				ui.Column(c).FillWidth().Gap(6).Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
						ui.Text(c, "Start of Authority (SOA) & Zone Timers").FontSize(app.fs(13)).Bold()
						ui.Badge(c, fmt.Sprintf("Serial: %d", za.SOA.Serial))
					})

					if za.SOA.PrimaryNS != "" {
						app.renderPivotActionRow(c, t, scanID, "Primary NS (MNAME)", za.SOA.PrimaryNS, "SOA Primary NS")
					}
					if za.SOA.AdminEmail != "" {
						app.renderKeyValue(c, t, "Hostmaster (RNAME)", za.SOA.AdminEmail)
					}
					app.renderKeyValue(c, t, "Zone Timers",
						fmt.Sprintf("Refresh: %ds | Retry: %ds | Expire: %ds | Negative Cache Min-TTL: %ds",
							za.SOA.Refresh, za.SOA.Retry, za.SOA.Expire, za.SOA.MinTTL))
				})
			})
		}

		// 4. Authoritative Nameservers Open Zone Transfer (AXFR) Check
		if za.AXFRChecked {
			borderCol := t.Border
			if za.AXFRVulnerable {
				borderCol = t.Danger
			}
			ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, borderCol).Children(func() {
				ui.Column(c).FillWidth().Gap(6).Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
						ui.Text(c, "Authoritative Zone Transfer (AXFR) Security Check").FontSize(app.fs(13)).Bold()
						if za.AXFRVulnerable {
							ui.Badge(c, "VULNERABLE (OPEN AXFR)")
						} else {
							ui.Badge(c, "SECURE (AXFR REFUSED)")
						}
					})

					if za.AXFRSummary != "" {
						ui.Text(c, za.AXFRSummary).FontSize(app.fs(12)).TextColor(t.TextMuted)
					}

					for _, ar := range za.AXFRResults {
						axfrItem := ar
						ui.Row(c).Key("axfr:" + axfrItem.Nameserver).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
							ui.Text(c, axfrItem.Nameserver).FontSize(app.fs(12)).Bold().Selectable()
							ui.Badge(c, axfrItem.Status)
						})
					}
				})
			})
		}
	})
}

func (app *DesktopApp) renderWebCVESection(c *ui.Context, t *ui.Theme, scanID int64, vulnsChecked bool, vulns []analyzer.Vulnerability) {
	checked := vulnsChecked || len(vulns) > 0
	ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
		btnLabel := "Check CVEs"
		if checked {
			btnLabel = "Re-check CVEs ↻"
		}
		if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
			app.StartVulnerabilityCheck(scanID)
		}

		if !checked {
			ui.Text(c, "Click 'Check CVEs' to query the NVD database for known vulnerabilities in detected technologies.").
				FontSize(app.fs(12)).
				TextColor(t.TextMuted)
		} else {
			ui.Badge(c, fmt.Sprintf("%d CVEs Found", len(vulns)))
			if len(vulns) == 0 {
				ui.Text(c, "No known CVEs found for detected technology versions.").
					FontSize(app.fs(12)).
					TextColor(t.TextMuted)
			}
		}
	})

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
				ui.Text(c, vuln.Description).FontSize(app.fs(12)).TextColor(t.TextMuted)
			})
		})
	}
}

func (app *DesktopApp) renderEmailAuthCard(c *ui.Context, t *ui.Theme, scanID int64, info *analyzer.DomainInfo) {
	apex := info.ApexDomain
	if apex == "" {
		apex = info.Domain
	}
	email := info.Email

	app.renderSectionCard(c, t, "Email Deliverability & Authentication (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI)", func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
			btnLabel := "Audit Email Auth"
			if email.DeepChecked {
				btnLabel = "Re-audit Email Auth ↻"
			}
			if ui.PrimaryButton(c, btnLabel).Disabled(app.scanning).Clicked() {
				app.StartEmailDeepDive(scanID)
			}

			if email.SPFRecord != nil {
				ui.Badge(c, "SPF: "+email.SPFRecord.Status)
			} else {
				ui.Badge(c, "SPF: Missing")
			}

			if email.DMARCRecord != nil {
				ui.Badge(c, fmt.Sprintf("DMARC: %s (%s)", email.DMARCRecord.Policy, email.DMARCRecord.Status))
			} else {
				ui.Badge(c, "DMARC: Missing")
			}

			ui.Badge(c, fmt.Sprintf("DKIM: %d Selectors", len(email.DKIMRecords)))

			if email.MTASTS != nil && email.MTASTS.Found {
				mode := email.MTASTS.Mode
				if mode == "" {
					mode = "present"
				}
				ui.Badge(c, "MTA-STS: "+mode)
			} else {
				ui.Badge(c, "MTA-STS: None")
			}

			if email.TLSRPT != nil && email.TLSRPT.Found {
				ui.Badge(c, "TLS-RPT: Present")
			}
			if email.BIMI != nil && email.BIMI.Found {
				ui.Badge(c, "BIMI: Present")
			}
		})

		// 1. Mail Providers & MX Hosts
		if len(email.MailProviders) > 0 {
			app.renderKeyValue(c, t, "Mail Providers", strings.Join(email.MailProviders, ", "))
		} else {
			app.renderKeyValue(c, t, "Mail Providers", "None detected")
		}

		if len(email.MXRecords) > 0 {
			ui.Text(c, "MX Servers (Drill-Down):").FontSize(app.fs(12)).TextColor(t.TextMuted)
			for _, mx := range email.MXRecords {
				app.renderPivotActionRow(c, t, scanID, "MX Host", mx, "MX Record")
			}
		}

		// 2. SPF
		if email.SPFRecord != nil {
			app.renderKeyValue(c, t, "SPF Status", fmt.Sprintf("%s — %s (%s)", email.SPFRecord.Status, email.SPFRecord.Policy, email.SPFRecord.Description))
			app.renderKeyValue(c, t, "SPF Raw", email.SPFRecord.Raw)
			if len(email.SPFRecord.Includes) > 0 {
				ui.Text(c, "SPF Includes (Drill-Down):").FontSize(app.fs(12)).TextColor(t.TextMuted)
				for _, inc := range email.SPFRecord.Includes {
					app.renderPivotActionRow(c, t, scanID, "", inc, "SPF Include")
				}
			}
		} else {
			app.renderKeyValue(c, t, "SPF Record", "Not found")
		}

		// 3. DMARC
		if email.DMARCRecord != nil {
			app.renderKeyValue(c, t, "DMARC Status", fmt.Sprintf("%s — Policy: %s (%s)", email.DMARCRecord.Status, email.DMARCRecord.Policy, email.DMARCRecord.Description))
			if len(email.DMARCRecord.AggregateReports) > 0 {
				app.renderKeyValue(c, t, "DMARC Reports (rua)", strings.Join(email.DMARCRecord.AggregateReports, ", "))
			}
			app.renderKeyValue(c, t, "DMARC Raw", email.DMARCRecord.Raw)
		} else {
			app.renderKeyValue(c, t, "DMARC Record", "Not found")
		}

		// 4. DKIM Selectors
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "DKIM Selectors (DomainKeys Identified Mail)").FontSize(app.fs(13)).Bold()
					if len(email.DKIMRecords) > 0 {
						ui.Badge(c, fmt.Sprintf("%d ACTIVE SELECTORS", len(email.DKIMRecords)))
					} else {
						ui.Badge(c, "NONE DISCOVERED")
					}
				})

				if len(email.DKIMRecords) == 0 {
					ui.Text(c, fmt.Sprintf("No public DKIM keys discovered across %d common selectors (google, selector1, selector2, default, k1, s1, etc.).", 22)).
						FontSize(app.fs(12)).
						TextColor(t.TextMuted)
				} else {
					for _, dk := range email.DKIMRecords {
						dkim := dk
						ui.Box(c).Key("dkim:"+dkim.Selector).FillWidth().Padding(6).Radius(4).Border(1, t.Border).Children(func() {
							ui.Column(c).FillWidth().Gap(4).Children(func() {
								ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
									ui.Badge(c, dkim.Selector+"._domainkey."+apex)
									if dkim.KeyType != "" {
										ui.Badge(c, "Key: "+strings.ToUpper(dkim.KeyType))
									}
									if dkim.CNAME != "" {
										ui.Text(c, "CNAME → "+dkim.CNAME).FontSize(app.fs(12)).TextColor(t.TextMuted).Selectable()
									}
								})
								if dkim.RawRecord != "" {
									ui.Text(c, dkim.RawRecord).FontSize(app.fs(11)).TextColor(t.TextMuted).Selectable()
								}
							})
						})
					}
				}
			})
		})

		// 5. MTA-STS & SMTP TLS-RPT
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "MTA-STS (RFC 8461) & SMTP TLS Reporting (RFC 8460)").FontSize(app.fs(13)).Bold()
					if email.MTASTS != nil && email.MTASTS.Found {
						ui.Badge(c, "MTA-STS: PRESENT")
						if email.MTASTS.Mode != "" {
							ui.Badge(c, "Mode: "+strings.ToUpper(email.MTASTS.Mode))
						}
					} else {
						ui.Badge(c, "MTA-STS: MISSING")
					}
					if email.TLSRPT != nil && email.TLSRPT.Found {
						ui.Badge(c, "TLS-RPT: PRESENT")
					} else {
						ui.Badge(c, "TLS-RPT: MISSING")
					}
					ui.Spacer(c)
					if email.MTASTS != nil && email.MTASTS.PolicyURL != "" {
						ui.Link(c, "Open mta-sts.txt ↗", email.MTASTS.PolicyURL)
					}
				})

				if email.MTASTS != nil && email.MTASTS.Found {
					if email.MTASTS.ID != "" {
						app.renderKeyValue(c, t, "MTA-STS Policy ID", email.MTASTS.ID)
					}
					if email.MTASTS.MaxAge != "" {
						app.renderKeyValue(c, t, "MTA-STS Max Age", email.MTASTS.MaxAge+"s")
					}
					if len(email.MTASTS.MXPatterns) > 0 {
						app.renderKeyValue(c, t, "MTA-STS Allowed MX", strings.Join(email.MTASTS.MXPatterns, ", "))
					}
					if email.MTASTS.DNSRecord != "" {
						app.renderKeyValue(c, t, "MTA-STS DNS Record", email.MTASTS.DNSRecord)
					}
				} else {
					ui.Text(c, "No _mta-sts DNS TXT record or /.well-known/mta-sts.txt policy detected.").
						FontSize(app.fs(12)).
						TextColor(t.TextMuted)
				}

				if email.TLSRPT != nil && email.TLSRPT.Found {
					if len(email.TLSRPT.Endpoints) > 0 {
						app.renderKeyValue(c, t, "TLS-RPT Endpoints", strings.Join(email.TLSRPT.Endpoints, ", "))
					}
					if email.TLSRPT.RawRecord != "" {
						app.renderKeyValue(c, t, "TLS-RPT Raw", email.TLSRPT.RawRecord)
					}
				}
			})
		})

		// 6. BIMI (Brand Indicators for Message Identification)
		ui.Box(c).FillWidth().Padding(8).Radius(6).Border(1, t.Border).Children(func() {
			ui.Column(c).FillWidth().Gap(6).Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, "BIMI (Brand Indicators for Message Identification)").FontSize(app.fs(13)).Bold()
					if email.BIMI != nil && email.BIMI.Found {
						ui.Badge(c, "PRESENT")
					} else {
						ui.Badge(c, "NOT CONFIGURED")
					}
					ui.Spacer(c)
					if email.BIMI != nil && email.BIMI.LogoURL != "" {
						ui.Link(c, "Open BIMI SVG Logo ↗", email.BIMI.LogoURL)
					}
					if email.BIMI != nil && email.BIMI.AuthorityURL != "" {
						ui.Link(c, "Open VMC Certificate ↗", email.BIMI.AuthorityURL)
					}
				})

				if email.BIMI != nil && email.BIMI.Found {
					if email.BIMI.LogoURL != "" {
						app.renderKeyValue(c, t, "Brand Logo (l=)", email.BIMI.LogoURL)
					}
					if email.BIMI.AuthorityURL != "" {
						app.renderKeyValue(c, t, "VMC Authority (a=)", email.BIMI.AuthorityURL)
					}
					if email.BIMI.RawRecord != "" {
						app.renderKeyValue(c, t, "BIMI Raw", email.BIMI.RawRecord)
					}
				} else {
					ui.Text(c, "No default._bimi DNS TXT record detected.").
						FontSize(app.fs(12)).
						TextColor(t.TextMuted)
				}
			})
		})
	})
}

func (app *DesktopApp) renderPivotsTab(c *ui.Context, t *ui.Theme, scanID int64) {
	if len(app.currentPivots) == 0 {
		ui.Text(c, "No additional domains or IP addresses were discovered in this scan.").
			FontSize(app.fs(13)).
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
			FontSize(app.fs(13)).
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
				ui.Text(c, ch.Summary).FontSize(app.fs(12)).TextColor(t.TextMuted)
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
				ui.Text(c, "Formatted & Syntax-Highlighted JSON").FontSize(app.fs(14)).Bold()
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
				ui.RichText(c, spans...).Font("monospace").FontSize(app.fs(12)).Selectable().FillWidth()
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
