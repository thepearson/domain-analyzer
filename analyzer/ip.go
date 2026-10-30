package analyzer

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
)

type IPInfo struct {
	mu              sync.Mutex
	IP              string          `json:"ip"`
	PTRRecords      []string        `json:"ptr_records,omitempty"`
	Owner           string          `json:"owner,omitempty"`
	ASN             string          `json:"asn,omitempty"`
	CIDR            string          `json:"cidr,omitempty"`
	Country         string          `json:"country,omitempty"`
	TLS             TLSInfo         `json:"tls"`
	Web             WebInfo         `json:"web"`
	WAF             WAFInfo         `json:"waf"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
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
	wg.Add(5)

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
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(cleanIP, "443"), conf)
		if err != nil {
			return
		}
		defer conn.Close()

		certs := conn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			cert := certs[0]
			var sans []string
			seen := make(map[string]bool)
			addSAN := func(name string) {
				name = strings.TrimSpace(name)
				lower := strings.ToLower(name)
				if name != "" && !seen[lower] {
					seen[lower] = true
					sans = append(sans, name)
				}
			}
			for _, dnsName := range cert.DNSNames {
				addSAN(dnsName)
			}
			if cert.Subject.CommonName != "" && strings.Contains(cert.Subject.CommonName, ".") && !IsIPAddress(cert.Subject.CommonName) {
				addSAN(cert.Subject.CommonName)
			}

			info.Lock()
			info.TLS.HasTLS = true
			if len(cert.Issuer.Organization) > 0 {
				info.TLS.TLSIssuer = cert.Issuer.Organization[0]
			} else {
				info.TLS.TLSIssuer = cert.Issuer.CommonName
			}
			info.TLS.TLSExpiry = cert.NotAfter.Format(time.RFC3339)
			info.TLS.SANDomains = sans
			info.Unlock()
		}
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
			fingerprints := wappClient.Fingerprint(resp.Header, body)
			for techWithVersion := range fingerprints {
				name := techWithVersion
				version := ""
				if parts := strings.SplitN(techWithVersion, ":", 2); len(parts) == 2 {
					name = parts[0]
					version = parts[1]
				}
				techs = append(techs, name)
				details = append(details, TechDetail{
					Name:    name,
					Version: version,
				})
			}
		}

		info.Lock()
		info.Web.SecurityHeaders = secHeaders
		info.Web.TechStack = techs
		info.Web.TechDetails = details
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
		probeResp, _ := performHTTPProbe(probeTargetURL + sep + wafProbeParam)
		wafInfo := EvaluateWAF(nil, baseResp, probeResp)
		info.Lock()
		info.WAF = wafInfo
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
