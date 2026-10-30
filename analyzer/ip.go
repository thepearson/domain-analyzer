package analyzer

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
)

type IPInfo struct {
	mu              sync.Mutex
	IP              string            `json:"ip"`
	PTRRecords      []string          `json:"ptr_records,omitempty"`
	Owner           string            `json:"owner,omitempty"`
	ASN             string            `json:"asn,omitempty"`
	CIDR            string            `json:"cidr,omitempty"`
	Country         string            `json:"country,omitempty"`
	TLS             TLSInfo           `json:"tls"`
	Web             WebInfo           `json:"web"`
	WAF             WAFInfo           `json:"waf"`
	Metadata        *WebsiteMetadata  `json:"metadata,omitempty"`
	Ping            *PingResult       `json:"ping,omitempty"`
	Traceroute      *TracerouteResult `json:"traceroute,omitempty"`
	PortScanned     bool              `json:"port_scanned,omitempty"`
	OpenPorts       []PortService     `json:"open_ports,omitempty"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities,omitempty"`
}

func (info *IPInfo) Lock() {
	info.mu.Lock()
}

func (info *IPInfo) Unlock() {
	info.mu.Unlock()
}

// IsIPAddress returns true if target is a valid IPv4 or IPv6 address.
func IsIPAddress(target string) bool {
	cleaned := strings.TrimSpace(target)
	cleaned = strings.TrimPrefix(cleaned, "https://")
	cleaned = strings.TrimPrefix(cleaned, "http://")
	cleaned = strings.Split(cleaned, "/")[0]
	if host, _, err := net.SplitHostPort(cleaned); err == nil {
		cleaned = host
	}
	return net.ParseIP(cleaned) != nil
}

// NormalizeTarget extracts the clean hostname or IP from user input.
func NormalizeTarget(target string) string {
	host, _ := normalizeTarget(target)
	return strings.TrimSuffix(strings.TrimSpace(host), ".")
}

// AnalyzeIP performs concurrent reconnaissance on an IP address.
func AnalyzeIP(ip string, checkVulns bool) *IPInfo {
	cleanIP := NormalizeTarget(ip)
	info := &IPInfo{
		IP: cleanIP,
	}

	var wg sync.WaitGroup
	wg.Add(6)

	// 1. Reverse DNS (PTR)
	go func() {
		defer wg.Done()
		names, err := net.LookupAddr(cleanIP)
		if err != nil {
			return
		}
		var ptrs []string
		seen := make(map[string]bool)
		for _, n := range names {
			clean := strings.TrimSuffix(strings.TrimSpace(n), ".")
			lower := strings.ToLower(clean)
			if clean != "" && !seen[lower] {
				seen[lower] = true
				ptrs = append(ptrs, clean)
			}
		}
		info.Lock()
		info.PTRRecords = ptrs
		info.Unlock()
	}()

	// 2. IP WHOIS (Owner, ASN, CIDR, Country)
	go func() {
		defer wg.Done()
		raw, err := whois.Whois(cleanIP)
		if err != nil {
			return
		}
		owner, asn, cidr, country := ParseIPWhoisDetails(raw)
		info.Lock()
		info.Owner = owner
		info.ASN = asn
		info.CIDR = cidr
		info.Country = country
		info.Unlock()
	}()

	// 3. Direct TLS Inspection on :443
	go func() {
		defer wg.Done()
		tlsInfo, err := InspectTLS(cleanIP)
		if err != nil {
			return
		}
		info.Lock()
		info.TLS = tlsInfo
		info.Unlock()
	}()

	// 4. Direct HTTP/HTTPS Web & Security Headers Inspection
	go func() {
		defer wg.Done()
		client := &http.Client{
			Timeout: 12 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}

		targetURL := "https://" + cleanIP
		resp, err := client.Get(targetURL)
		if err != nil {
			targetURL = "http://" + cleanIP
			resp, err = client.Get(targetURL)
		}
		if err != nil {
			return
		}
		defer resp.Body.Close()

		headersToCheck := []string{
			"Strict-Transport-Security",
			"Content-Security-Policy",
			"X-Frame-Options",
			"X-Content-Type-Options",
			"Referrer-Policy",
			"Permissions-Policy",
		}
		secHeaders := make(map[string]string)
		for _, h := range headersToCheck {
			val := resp.Header.Get(h)
			if val != "" {
				secHeaders[h] = val
			} else {
				secHeaders[h] = "Missing"
			}
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		var techs []string
		var details []TechDetail
		if wappClient := getWappalyzerClient(); wappClient != nil {
			fingerprints := wappClient.FingerprintWithInfo(resp.Header, body)
			for techWithVersion, appInfo := range fingerprints {
				name := techWithVersion
				version := ""
				if parts := strings.SplitN(techWithVersion, ":", 2); len(parts) == 2 {
					name = parts[0]
					version = parts[1]
				}
				website := strings.TrimSpace(appInfo.Website)
				icon := strings.TrimSpace(appInfo.Icon)
				if website == "" {
					website, icon = LookupTechAppInfo(name)
				}
				techs = append(techs, name)
				details = append(details, TechDetail{
					Name:    name,
					Version: version,
					Website: website,
					Icon:    icon,
				})
			}
		}

		sort.Strings(techs)
		sort.Slice(details, func(i, j int) bool {
			return details[i].Name < details[j].Name
		})

		PopulateTechFavicons(details)

		finalPageURL := targetURL
		if resp.Request != nil && resp.Request.URL != nil {
			finalPageURL = resp.Request.URL.String()
		}
		favicon := FetchFavicon(finalPageURL, body, client)

		info.Lock()
		info.Web.SecurityHeaders = secHeaders
		info.Web.TechStack = techs
		info.Web.TechDetails = details
		info.Web.Favicon = favicon
		info.Unlock()
	}()

	// 5. Direct WAF Probe on IP
	go func() {
		defer wg.Done()
		baseURL := "https://" + cleanIP
		baseResp, err := performHTTPProbe(baseURL)
		if err != nil {
			baseResp, err = performHTTPProbe("http://" + cleanIP)
			if err != nil {
				return
			}
		}
		probeTargetURL := baseURL
		if baseResp.FinalURL != "" {
			probeTargetURL = baseResp.FinalURL
		}
		sep := "?"
		if strings.Contains(probeTargetURL, "?") {
			sep = "&"
		}
		testURL := probeTargetURL + sep + wafProbeParam
		probeResp, _ := performHTTPProbe(testURL)
		wafInfo := EvaluateWAF(nil, baseResp, probeResp)
		wafInfo.BaselineURL = probeTargetURL
		wafInfo.ProbeURL = testURL
		info.Lock()
		info.WAF = wafInfo
		info.Unlock()
	}()

	// 6. Ping / Connectivity Latency
	go func() {
		defer wg.Done()
		pingRes := RunPing(cleanIP)
		info.Lock()
		info.Ping = pingRes
		info.Unlock()
	}()

	wg.Wait()

	if checkVulns && len(info.Web.TechDetails) > 0 {
		tempDomain := &DomainInfo{
			Web: info.Web,
		}
		if err := getVulnerabilities(tempDomain); err == nil {
			info.Lock()
			info.Vulnerabilities = tempDomain.Vulnerabilities
			info.Unlock()
		}
	}

	return info
}

// ParseIPWhoisDetails extracts organization/owner, ASN, CIDR/NetRange, and country from raw IP WHOIS output.
func ParseIPWhoisDetails(whoisOutput string) (owner, asn, cidr, country string) {
	owner = ParseIPOwner(whoisOutput)
	lines := strings.Split(whoisOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}
		switch key {
		case "originas", "origin":
			if asn == "" {
				asn = val
			}
		case "cidr":
			cidr = val
		case "inetnum", "netrange":
			if cidr == "" {
				cidr = val
			}
		case "country":
			if country == "" {
				country = strings.ToUpper(val)
			}
		case "netname":
			if owner == "" {
				owner = val
			}
		}
	}
	return owner, asn, cidr, country
}
