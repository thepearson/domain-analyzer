package analyzer

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var (
	wappalyzerOnce   sync.Once
	cachedWappalyzer *wappalyzer.Wappalyze
)

func getWappalyzerClient() *wappalyzer.Wappalyze {
	wappalyzerOnce.Do(func() {
		cachedWappalyzer, _ = wappalyzer.New()
	})
	return cachedWappalyzer
}

const (
	wafUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0"
	wafProbeParam = "probe_test=%3Cscript%3Ealert(1)%3C/script%3E"
)

type WAFProviderResult struct {
	Provider       string   `json:"provider"`
	Detected       bool     `json:"detected"`
	Enforcing      bool     `json:"enforcing"`
	Implementation []string `json:"implementation,omitempty"`
	State          string   `json:"state,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
}

type WAFInfo struct {
	Detected       bool                `json:"detected"`
	Summary        string              `json:"summary"`
	CNAMEs         []string            `json:"cnames,omitempty"`
	BaselineURL    string              `json:"baseline_url,omitempty"`
	ProbeURL       string              `json:"probe_url,omitempty"`
	BaselineStatus int                 `json:"baseline_status,omitempty"`
	ProbeStatus    int                 `json:"probe_status,omitempty"`
	Providers      []WAFProviderResult `json:"providers,omitempty"`
	OriginNotes    []string            `json:"origin_notes,omitempty"`
}

type wafProbeResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
	FinalURL   string
}

func getWAFInfo(domain string, apexDomain string, info *DomainInfo) error {
	host, baseURL := normalizeTarget(domain)

	cnames := lookupCNAMEChain(host)

	// 1. Baseline HTTP Probe
	baseResp, err := performHTTPProbe(baseURL)
	if err != nil {
		// Fallback to HTTP if HTTPS failed
		if strings.HasPrefix(baseURL, "https://") {
			httpURL := "http://" + strings.TrimPrefix(baseURL, "https://")
			baseResp, err = performHTTPProbe(httpURL)
		}
		if err != nil {
			return err
		}
	}

	// If baseline redirected to a different hostname (e.g. apex -> www.domain),
	// also check CNAMEs on the final hostname since CNAME records cannot exist at the zone apex.
	probeTargetURL := baseURL
	if baseResp.FinalURL != "" {
		probeTargetURL = baseResp.FinalURL
		if parsed, err := url.Parse(baseResp.FinalURL); err == nil {
			finalHost := parsed.Hostname()
			if finalHost != "" && !strings.EqualFold(finalHost, host) {
				extraCNAMEs := lookupCNAMEChain(finalHost)
				cnames = mergeUniqueStrings(cnames, extraCNAMEs)
			}
		}
	}

	// Also if domain is the apex domain and we still have no CNAMEs, check www.<domain> CNAMEs
	// only if www resolves to the same IP or if no CNAME was found at apex.
	if len(cnames) == 0 && strings.EqualFold(host, apexDomain) {
		wwwCNAMEs := lookupCNAMEChain("www." + apexDomain)
		if len(wwwCNAMEs) > 0 && strings.Contains(strings.ToLower(probeTargetURL), "www."+strings.ToLower(apexDomain)) {
			cnames = mergeUniqueStrings(cnames, wwwCNAMEs)
		}
	}

	// 2. Benign WAF Trigger Probe
	sep := "?"
	if strings.Contains(probeTargetURL, "?") {
		sep = "&"
	}
	testURL := probeTargetURL + sep + wafProbeParam
	probeResp, _ := performHTTPProbe(testURL)

	wafInfo := EvaluateWAF(cnames, baseResp, probeResp)
	wafInfo.BaselineURL = probeTargetURL
	wafInfo.ProbeURL = testURL

	info.Lock()
	info.WAF = wafInfo
	info.Unlock()

	return nil
}

func normalizeTarget(target string) (host string, targetURL string) {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname(), target
		}
	}
	host = strings.Split(target, "/")[0]
	host = strings.Split(host, ":")[0]
	return host, "https://" + host
}

func lookupCNAMEChain(host string) []string {
	var cnames []string
	seen := make(map[string]bool)

	addCNAME := func(c string) {
		c = strings.TrimSpace(strings.TrimSuffix(c, "."))
		lower := strings.ToLower(c)
		if c != "" && !strings.EqualFold(c, host) && !seen[lower] {
			seen[lower] = true
			cnames = append(cnames, c)
		}
	}

	// 1. Standard library CNAME lookup
	if cname, err := net.LookupCNAME(host); err == nil {
		addCNAME(cname)
	}

	// 2. Direct DNS query using miekg/dns to capture intermediate CNAME hops
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	if r, _, err := c.Exchange(m, "8.8.8.8:53"); err == nil && r != nil {
		for _, ans := range r.Answer {
			if cnameRec, ok := ans.(*dns.CNAME); ok {
				addCNAME(cnameRec.Target)
			}
		}
	}

	return cnames
}

func performHTTPProbe(targetURL string) (*wafProbeResponse, error) {
	collectedHeaders := make(http.Header)

	dialer := &net.Dialer{
		Timeout: 8 * time.Second,
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.Response != nil {
				for k, vals := range req.Response.Header {
					for _, v := range vals {
						collectedHeaders.Add(k, v)
					}
				}
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			req.Header.Set("User-Agent", wafUserAgent)
			return nil
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", wafUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Merge final response headers
	for k, vals := range resp.Header {
		for _, v := range vals {
			collectedHeaders.Add(k, v)
		}
	}

	// Read up to 512KB of body for signature analysis
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	finalURL := targetURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	return &wafProbeResponse{
		StatusCode: resp.StatusCode,
		Headers:    collectedHeaders,
		Body:       string(bodyBytes),
		FinalURL:   finalURL,
	}, nil
}

// EvaluateWAF analyzes DNS CNAMEs, baseline HTTP response, and WAF probe response
// to determine whether a WAF is present and how it is implemented.
func EvaluateWAF(cnames []string, base *wafProbeResponse, probe *wafProbeResponse) WAFInfo {
	result := WAFInfo{
		CNAMEs: cnames,
	}

	var baseHeaders http.Header
	var baseStatus int
	var baseBody string
	if base != nil {
		baseHeaders = base.Headers
		baseStatus = base.StatusCode
		baseBody = base.Body
		result.BaselineStatus = baseStatus
	}

	var probeHeaders http.Header
	var probeStatus int
	var probeBody string
	if probe != nil {
		probeHeaders = probe.Headers
		probeStatus = probe.StatusCode
		probeBody = probe.Body
		result.ProbeStatus = probeStatus
	}

	// -------------------------------------------------------------------------
	// 1. CLOUDFLARE
	// -------------------------------------------------------------------------
	cfProxy := false
	cfBot := false
	cfBlock := false
	var cfEvidence []string

	if headerValueMatches(baseHeaders, "Server", `(?i)cloudflare`) {
		cfProxy = true
		cfEvidence = append(cfEvidence, "Header: server: cloudflare")
	}
	if hasHeader(baseHeaders, "Cf-Ray") {
		cfProxy = true
		cfEvidence = append(cfEvidence, "Header: cf-ray")
	}
	if cnameMatches(cnames, `(?i)cloudflare\.(net|com)`) {
		cfProxy = true
		cfEvidence = append(cfEvidence, "CNAME: cloudflare")
	}
	if headerValueMatches(baseHeaders, "Set-Cookie", `(?i)__cf_bm=`) {
		cfBot = true
		cfEvidence = append(cfEvidence, "Cookie: __cf_bm")
	}
	if (probeStatus == 403 || probeStatus == 429 || probeStatus == 503) &&
		regexMatch(probeBody, `(?i)(error code 1020|attention required|cloudflare|ray id)`) {
		cfBlock = true
		cfEvidence = append(cfEvidence, fmt.Sprintf("Block Page: HTTP %d with Cloudflare signature", probeStatus))
	}

	if cfProxy || cfBot || cfBlock {
		var impl []string
		if cfProxy {
			impl = append(impl, "Edge Proxy/CDN: ACTIVE")
		}
		if cfBot {
			impl = append(impl, "Bot Management: ACTIVE (__cf_bm cookie detected)")
		}
		state := "PASSTHROUGH / OFF (Edge passed payload)"
		if cfBlock {
			state = "ENFORCING (Payload blocked at edge)"
		}
		result.Providers = append(result.Providers, WAFProviderResult{
			Provider:       "Cloudflare",
			Detected:       true,
			Enforcing:      cfBlock,
			Implementation: impl,
			State:          state,
			Evidence:       cfEvidence,
		})
	}

	// -------------------------------------------------------------------------
	// 2. FASTLY / SIGNAL SCIENCES (NEXT-GEN WAF)
	// -------------------------------------------------------------------------
	fastlyDetect := false
	fastlyBlocked := false
	var fastlyEvidence []string

	for _, h := range []string{"X-Served-By", "Fastly-Restarts", "X-Fastly-Request-Id"} {
		if hasHeader(baseHeaders, h) {
			fastlyDetect = true
			fastlyEvidence = append(fastlyEvidence, "Header: "+strings.ToLower(h))
		}
	}
	if cnameMatches(cnames, `(?i)(fastly\.net|fastlylb\.net)`) {
		fastlyDetect = true
		fastlyEvidence = append(fastlyEvidence, "CNAME: fastly")
	}

	if probeStatus == 406 && baseStatus != 406 {
		fastlyBlocked = true
		fastlyEvidence = append(fastlyEvidence, "Probe Status: HTTP 406 Not Acceptable")
	} else if (probeStatus == 403 || probeStatus == 406) &&
		(regexMatch(probeBody, `(?i)(fastly error|signal sciences|sigsci)`) || hasHeaderSubstring(probeHeaders, "x-sigsci")) {
		fastlyBlocked = true
		fastlyEvidence = append(fastlyEvidence, fmt.Sprintf("Block Signature: HTTP %d Fastly/SigSci", probeStatus))
	}

	if fastlyDetect || fastlyBlocked {
		var impl []string
		if fastlyDetect {
			impl = append(impl, "Fastly Edge/CDN: ACTIVE (Headers/CNAME verified)")
		}
		state := "NOT BLOCKING (Traffic allowed or monitor mode)"
		if fastlyBlocked {
			state = fmt.Sprintf("ENFORCING (Blocked - status code %d)", probeStatus)
		}
		result.Providers = append(result.Providers, WAFProviderResult{
			Provider:       "Fastly / Next-Gen WAF",
			Detected:       true,
			Enforcing:      fastlyBlocked,
			Implementation: impl,
			State:          state,
			Evidence:       fastlyEvidence,
		})
	}

	// -------------------------------------------------------------------------
	// 3. AWS WAF (CloudFront / ALB)
	// -------------------------------------------------------------------------
	awsDetect := false
	awsBlocked := false
	var awsEvidence []string

	if hasHeaderPrefix(baseHeaders, "x-amz-cf-id", "x-amzn-requestid") {
		awsDetect = true
		awsEvidence = append(awsEvidence, "Header: x-amz-cf-id / x-amzn-requestid")
	}
	if cnameMatches(cnames, `(?i)(cloudfront\.net|elb\.amazonaws\.com)`) {
		awsDetect = true
		awsEvidence = append(awsEvidence, "CNAME: cloudfront.net / elb.amazonaws.com")
	}
	if headerValueMatches(probeHeaders, "X-Amzn-Errortype", `(?i)^\s*waf`) {
		awsBlocked = true
		awsEvidence = append(awsEvidence, "Header: x-amzn-errortype: waf")
	} else if probeStatus == 403 && regexMatch(probeBody, `(?i)(aws waf|request blocked.*cloudfront)`) {
		awsBlocked = true
		awsEvidence = append(awsEvidence, "Block Page: HTTP 403 AWS WAF / CloudFront")
	}

	if awsDetect || awsBlocked {
		var impl []string
		if awsDetect {
			impl = append(impl, "Edge/Load Balancer: ACTIVE (CloudFront / ALB headers detected)")
		}
		state := "NOT BLOCKING (Traffic allowed or in Count mode)"
		if awsBlocked {
			state = "ENFORCING (Blocked via x-amzn-errortype or AWS block page)"
		}
		result.Providers = append(result.Providers, WAFProviderResult{
			Provider:       "AWS WAF",
			Detected:       true,
			Enforcing:      awsBlocked,
			Implementation: impl,
			State:          state,
			Evidence:       awsEvidence,
		})
	}

	// -------------------------------------------------------------------------
	// 4. AZURE WAF (Front Door / Application Gateway)
	// -------------------------------------------------------------------------
	azDetect := false
	azBlocked := false
	var azEvidence []string

	if hasHeaderPrefix(baseHeaders, "x-azure-ref", "x-fd-") {
		azDetect = true
		azEvidence = append(azEvidence, "Header: x-azure-ref / x-fd-*")
	}
	if cnameMatches(cnames, `(?i)(azureedge\.net|azurefd\.net)`) {
		azDetect = true
		azEvidence = append(azEvidence, "CNAME: azureedge.net / azurefd.net")
	}
	if probeStatus == 403 &&
		(hasHeaderPrefix(probeHeaders, "x-azure-ref") || regexMatch(probeBody, `(?i)(azure.*waf|blocked by front door)`)) {
		azBlocked = true
		azEvidence = append(azEvidence, "Block Page: HTTP 403 at Azure edge")
	}

	if azDetect || azBlocked {
		var impl []string
		if azDetect {
			impl = append(impl, "Front Door / CDN: ACTIVE (x-azure-ref / CNAME detected)")
		}
		state := "NOT BLOCKING (Traffic allowed or in Detection mode)"
		if azBlocked {
			state = "ENFORCING (HTTP 403 generated at Azure edge)"
		}
		result.Providers = append(result.Providers, WAFProviderResult{
			Provider:       "Azure WAF",
			Detected:       true,
			Enforcing:      azBlocked,
			Implementation: impl,
			State:          state,
			Evidence:       azEvidence,
		})
	}

	// -------------------------------------------------------------------------
	// 5. REDSHIELD
	// -------------------------------------------------------------------------
	rsDetect := false
	rsBlocked := false
	var rsEvidence []string

	if cnameMatches(cnames, `(?i)redshield\.(co|net)`) {
		rsDetect = true
		rsEvidence = append(rsEvidence, "CNAME: redshield")
	}
	if headersContainPattern(baseHeaders, `(?i)(x-redshield|redshield)`) {
		rsDetect = true
		rsEvidence = append(rsEvidence, "Header: redshield")
	}
	if regexMatch(probeBody, `(?i)(redshield|shield.*reference|request id:.*rs)`) {
		rsBlocked = true
		rsEvidence = append(rsEvidence, "Block Page: RedShield reference")
	} else if headersContainPattern(probeHeaders, `(?i)redshield`) &&
		(probeStatus >= 400 || !headersContainPattern(baseHeaders, `(?i)redshield`)) {
		rsBlocked = true
		rsEvidence = append(rsEvidence, "Header: redshield on probe response")
	}

	if rsDetect || rsBlocked {
		var impl []string
		if rsDetect {
			impl = append(impl, "Proxy / In-Flight: ACTIVE (CNAME / Header match)")
		}
		state := "PASSTHROUGH / ACTIVE REMEDIATION"
		if rsBlocked {
			state = "ENFORCING (Request intercepted or blocked)"
		}
		result.Providers = append(result.Providers, WAFProviderResult{
			Provider:       "RedShield",
			Detected:       true,
			Enforcing:      rsBlocked,
			Implementation: impl,
			State:          state,
			Evidence:       rsEvidence,
		})
	}

	// -------------------------------------------------------------------------
	// 6. IMPERVA / INCAPSULA
	// -------------------------------------------------------------------------
	impDetect := false
	impBlocked := false
	var impEvidence []string

	if cnameMatches(cnames, `(?i)(impervadns\.net|incapdns\.net)`) {
		impDetect = true
		impEvidence = append(impEvidence, "CNAME: impervadns.net / incapdns.net")
	}
	if hasHeader(baseHeaders, "X-Iinfo") || headerValueMatches(baseHeaders, "X-Cdn", `(?i)(imperva|incapsula)`) {
		impDetect = true
		impEvidence = append(impEvidence, "Header: X-Iinfo / X-Cdn: Imperva")
	}
	if headerValueMatches(baseHeaders, "Set-Cookie", `(?i)(visid_incap_|incap_ses_)`) {
		impDetect = true
		impEvidence = append(impEvidence, "Cookie: visid_incap_ / incap_ses_")
	}
	if (probeStatus == 403 || probeStatus == 503) &&
		(regexMatch(probeBody, `(?i)(_Incapsula_Resource|incapsula incident id|imperva|request unsuccessful)`) || hasHeader(probeHeaders, "X-Iinfo")) {
		impBlocked = true
		impEvidence = append(impEvidence, fmt.Sprintf("Block Page: HTTP %d Imperva/Incapsula", probeStatus))
	}

	if impDetect || impBlocked {
		var impl []string
		if impDetect {
			impl = append(impl, "Edge Proxy/CDN: ACTIVE (Imperva headers/cookies/CNAME detected)")
		}
		state := "NOT BLOCKING (Traffic allowed or alert mode)"
		if impBlocked {
			state = "ENFORCING (Payload blocked at Imperva edge)"
		}
		result.Providers = append(result.Providers, WAFProviderResult{
			Provider:       "Imperva / Incapsula",
			Detected:       true,
			Enforcing:      impBlocked,
			Implementation: impl,
			State:          state,
			Evidence:       impEvidence,
		})
	}

	// -------------------------------------------------------------------------
	// 7. ORIGIN-LEVEL FALLBACK & WAPPALYZER CHECKS
	// -------------------------------------------------------------------------
	if regexMatch(probeBody, `(?i)(wordfence|generated by wordfence)`) {
		result.OriginNotes = append(result.OriginNotes, "Wordfence (WordPress) blocked the request at the origin host.")
	}

	// Use wappalyzergo to see if any additional WAF technologies are fingerprinted
	if wappClient := getWappalyzerClient(); wappClient != nil {
		extraWAFs := detectWappalyzerWAFs(wappClient, baseHeaders, []byte(baseBody), probeHeaders, []byte(probeBody), result.Providers)
		result.Providers = append(result.Providers, extraWAFs...)
	}

	// Generic behavioral fallback: if baseline succeeded (< 400) and probe was blocked (403/406)
	// and no provider or origin note explained it
	if len(result.Providers) == 0 && len(result.OriginNotes) == 0 &&
		baseStatus > 0 && baseStatus < 400 && (probeStatus == 403 || probeStatus == 406) {
		result.Providers = append(result.Providers, WAFProviderResult{
			Provider:       "Generic / Unidentified WAF",
			Detected:       true,
			Enforcing:      true,
			Implementation: []string{"Behavioral Detection: Normal request succeeded, benign XSS probe blocked"},
			State:          fmt.Sprintf("ENFORCING (Blocked probe with HTTP %d)", probeStatus),
			Evidence:       []string{fmt.Sprintf("Baseline HTTP %d -> Probe HTTP %d", baseStatus, probeStatus)},
		})
	}

	// Summarize findings
	result.Detected = len(result.Providers) > 0 || len(result.OriginNotes) > 0
	var summaryParts []string
	for _, p := range result.Providers {
		mode := "Passthrough/Monitor"
		if p.Enforcing {
			mode = "Enforcing"
		}
		summaryParts = append(summaryParts, fmt.Sprintf("%s (%s)", p.Provider, mode))
	}
	for _, note := range result.OriginNotes {
		summaryParts = append(summaryParts, note)
	}
	if len(summaryParts) > 0 {
		result.Summary = strings.Join(summaryParts, "; ")
	} else {
		result.Summary = "No WAF detected"
	}

	return result
}

func detectWappalyzerWAFs(
	client *wappalyzer.Wappalyze,
	baseHeaders http.Header,
	baseBody []byte,
	probeHeaders http.Header,
	probeBody []byte,
	existing []WAFProviderResult,
) []WAFProviderResult {
	knownWAFNames := map[string]bool{
		"Sucuri":           true,
		"ModSecurity":      true,
		"F5 BIG-IP":        true,
		"Akamai":           true,
		"Barracuda WAF":    true,
		"FortiWeb":         true,
		"Wallarm":          true,
		"Reblaze":          true,
		"StackPath":        true,
		"Radware AppWall":  true,
		"Citrix NetScaler": true,
	}

	alreadyFound := make(map[string]bool)
	for _, p := range existing {
		alreadyFound[strings.ToLower(p.Provider)] = true
	}

	combined := make(map[string]wappalyzer.AppInfo)
	if len(baseHeaders) > 0 || len(baseBody) > 0 {
		for k, v := range client.FingerprintWithInfo(baseHeaders, baseBody) {
			combined[k] = v
		}
	}
	if len(probeHeaders) > 0 || len(probeBody) > 0 {
		for k, v := range client.FingerprintWithInfo(probeHeaders, probeBody) {
			combined[k] = v
		}
	}

	var extras []WAFProviderResult
	for techWithVer, appInfo := range combined {
		name := strings.SplitN(techWithVer, ":", 2)[0]
		if !knownWAFNames[name] {
			continue
		}
		lowerName := strings.ToLower(name)
		if alreadyFound[lowerName] {
			continue
		}
		alreadyFound[lowerName] = true

		extras = append(extras, WAFProviderResult{
			Provider:       name,
			Detected:       true,
			Enforcing:      false,
			Implementation: []string{fmt.Sprintf("Fingerprinted via Wappalyzer (%s)", strings.Join(appInfo.Categories, ", "))},
			State:          "DETECTED (Passive fingerprint)",
			Evidence:       []string{"Wappalyzer: " + techWithVer},
		})
	}
	return extras
}

func hasHeader(h http.Header, key string) bool {
	if h == nil {
		return false
	}
	for k, vals := range h {
		if strings.EqualFold(k, key) && len(vals) > 0 {
			return true
		}
	}
	return false
}

func hasHeaderPrefix(h http.Header, prefixes ...string) bool {
	if h == nil {
		return false
	}
	for k := range h {
		lowerK := strings.ToLower(k)
		for _, p := range prefixes {
			if strings.HasPrefix(lowerK, strings.ToLower(p)) {
				return true
			}
		}
	}
	return false
}

func hasHeaderSubstring(h http.Header, sub string) bool {
	if h == nil {
		return false
	}
	lowerSub := strings.ToLower(sub)
	for k := range h {
		if strings.Contains(strings.ToLower(k), lowerSub) {
			return true
		}
	}
	return false
}

func headerValueMatches(h http.Header, key string, pattern string) bool {
	if h == nil {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	for k, vals := range h {
		if strings.EqualFold(k, key) {
			for _, v := range vals {
				if re.MatchString(v) {
					return true
				}
			}
		}
	}
	return false
}

func headersContainPattern(h http.Header, pattern string) bool {
	if h == nil {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	for k, vals := range h {
		if re.MatchString(k) {
			return true
		}
		for _, v := range vals {
			if re.MatchString(v) {
				return true
			}
		}
	}
	return false
}

func cnameMatches(cnames []string, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	for _, c := range cnames {
		if re.MatchString(c) {
			return true
		}
	}
	return false
}

func regexMatch(s string, pattern string) bool {
	if s == "" {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range append(a, b...) {
		lower := strings.ToLower(s)
		if !seen[lower] {
			seen[lower] = true
			out = append(out, s)
		}
	}
	return out
}
