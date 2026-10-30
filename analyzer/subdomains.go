package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

type SubdomainEntry struct {
	Subdomain   string   `json:"subdomain"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	CNAME       string   `json:"cname,omitempty"`
	Active      bool     `json:"active"`
	Sources     []string `json:"sources,omitempty"`
}

type SubdomainEnumeration struct {
	ApexDomain  string           `json:"apex_domain"`
	TotalFound  int              `json:"total_found"`
	ActiveCount int              `json:"active_count"`
	Subdomains  []SubdomainEntry `json:"subdomains,omitempty"`
	SourcesUsed []string         `json:"sources_used,omitempty"`
	Error       string           `json:"error,omitempty"`
}

var commonSubdomainPrefixes = []string{
	"www", "mail", "api", "app", "dev", "staging", "test", "beta",
	"admin", "portal", "auth", "sso", "vpn", "remote", "webmail",
	"smtp", "imap", "pop", "mx", "ns1", "ns2", "cdn", "static",
	"assets", "media", "docs", "status", "blog", "shop", "store",
	"support", "git", "m", "cloud", "dashboard", " monitor",
}

// EnumerateSubdomains performs passive Certificate Transparency (crt.sh & CertSpotter)
// subdomain discovery combined with wildcard-aware DNS resolution verification.
func EnumerateSubdomains(domain string) *SubdomainEnumeration {
	clean := CleanDomainTarget(NormalizeTarget(domain))
	if clean == "" || IsIPAddress(clean) {
		return &SubdomainEnumeration{
			ApexDomain: clean,
			Error:      "Invalid domain target",
		}
	}

	apex, err := publicsuffix.EffectiveTLDPlusOne(clean)
	if err != nil || apex == "" {
		apex = clean
	}

	result := &SubdomainEnumeration{
		ApexDomain: apex,
	}

	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		sourceMap   = make(map[string]map[string]bool) // subdomain -> source -> true
		sourcesUsed []string
		ctErrors    []string
	)

	addDiscovered := func(sub, source string) {
		sub = NormalizeSubdomainCandidate(sub, apex)
		if sub == "" {
			return
		}
		mu.Lock()
		if sourceMap[sub] == nil {
			sourceMap[sub] = make(map[string]bool)
		}
		sourceMap[sub][source] = true
		mu.Unlock()
	}

	markSourceUsed := func(src string) {
		mu.Lock()
		for _, s := range sourcesUsed {
			if s == src {
				mu.Unlock()
				return
			}
		}
		sourcesUsed = append(sourcesUsed, src)
		mu.Unlock()
	}

	// 1. Passive CT Log Query: crt.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := fetchCrtShSubdomains(apex)
		if err != nil {
			mu.Lock()
			ctErrors = append(ctErrors, "crt.sh: "+err.Error())
			mu.Unlock()
			return
		}
		markSourceUsed("crt.sh")
		for _, s := range subs {
			addDiscovered(s, "crt.sh")
		}
	}()

	// 2. Passive CT Log Query: CertSpotter
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := fetchCertSpotterSubdomains(apex)
		if err != nil {
			mu.Lock()
			ctErrors = append(ctErrors, "certspotter: "+err.Error())
			mu.Unlock()
			return
		}
		if len(subs) > 0 {
			markSourceUsed("CertSpotter")
			for _, s := range subs {
				addDiscovered(s, "CertSpotter")
			}
		}
	}()

	// 3. Wildcard-safe common subdomain DNS check
	wildcardIPs := detectWildcardDNS(apex)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var dnsWg sync.WaitGroup
		sem := make(chan struct{}, 12)
		foundAnyDNS := false
		var dnsMu sync.Mutex

		for _, prefix := range commonSubdomainPrefixes {
			p := strings.TrimSpace(prefix)
			if p == "" {
				continue
			}
			candidate := p + "." + apex
			dnsWg.Add(1)
			go func(sub string) {
				defer dnsWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				ips, _ := lookupSubdomainDNS(sub)
				if len(ips) > 0 && !matchesWildcardIPs(ips, wildcardIPs) {
					addDiscovered(sub, "DNS")
					dnsMu.Lock()
					foundAnyDNS = true
					dnsMu.Unlock()
				}
			}(candidate)
		}
		dnsWg.Wait()
		if foundAnyDNS {
			markSourceUsed("DNS")
		}
	}()

	wg.Wait()

	// Collect all unique discovered subdomains
	candidates := make([]string, 0, len(sourceMap))
	for sub := range sourceMap {
		candidates = append(candidates, sub)
	}
	sort.Strings(candidates)

	// Cap active DNS verification at 150 subdomains so huge domains remain snappy
	const maxVerify = 150
	if len(candidates) > maxVerify {
		candidates = candidates[:maxVerify]
	}

	entries := make([]SubdomainEntry, len(candidates))
	var resolveWg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for i, sub := range candidates {
		srcsMap := sourceMap[sub]
		var srcs []string
		for s := range srcsMap {
			srcs = append(srcs, s)
		}
		sort.Strings(srcs)

		entries[i] = SubdomainEntry{
			Subdomain: sub,
			Sources:   srcs,
		}

		resolveWg.Add(1)
		go func(idx int, hostname string) {
			defer resolveWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ips, cname := lookupSubdomainDNS(hostname)
			if len(ips) > 0 && !matchesWildcardIPs(ips, wildcardIPs) {
				entries[idx].IPAddresses = ips
				entries[idx].CNAME = cname
				entries[idx].Active = true
			}
		}(i, sub)
	}
	resolveWg.Wait()

	// Sort active subdomains first, then alphabetically
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Active != entries[j].Active {
			return entries[i].Active
		}
		return entries[i].Subdomain < entries[j].Subdomain
	})

	activeCount := 0
	for _, e := range entries {
		if e.Active {
			activeCount++
		}
	}

	sort.Strings(sourcesUsed)
	result.Subdomains = entries
	result.TotalFound = len(entries)
	result.ActiveCount = activeCount
	result.SourcesUsed = sourcesUsed
	if len(entries) == 0 && len(ctErrors) > 0 {
		result.Error = strings.Join(ctErrors, "; ")
	}
	return result
}

// NormalizeSubdomainCandidate cleans a raw CT log name and returns it if it is a valid subdomain of apexDomain.
func NormalizeSubdomainCandidate(raw, apexDomain string) string {
	apex := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(apexDomain), "."))
	if apex == "" {
		return ""
	}
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || s == apex || strings.ContainsAny(s, " \t\r\n/\\:@") {
		return ""
	}
	if !strings.HasSuffix(s, "."+apex) {
		return ""
	}
	return s
}

type crtShEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func fetchCrtShSubdomains(apexDomain string) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	reqURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape("%."+apexDomain))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", wafUserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	return ParseCrtShJSON(body, apexDomain)
}

// ParseCrtShJSON parses the JSON response from crt.sh and extracts unique subdomains of apexDomain.
func ParseCrtShJSON(body []byte, apexDomain string) ([]string, error) {
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []string
	add := func(candidate string) {
		for _, line := range strings.Split(candidate, "\n") {
			norm := NormalizeSubdomainCandidate(line, apexDomain)
			if norm != "" && !seen[norm] {
				seen[norm] = true
				results = append(results, norm)
			}
		}
	}

	for _, e := range entries {
		add(e.CommonName)
		add(e.NameValue)
	}
	sort.Strings(results)
	return results, nil
}

type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

func fetchCertSpotterSubdomains(apexDomain string) ([]string, error) {
	client := &http.Client{Timeout: 12 * time.Second}
	reqURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", url.QueryEscape(apexDomain))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", wafUserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	return ParseCertSpotterJSON(body, apexDomain)
}

// ParseCertSpotterJSON parses the JSON response from CertSpotter and extracts unique subdomains of apexDomain.
func ParseCertSpotterJSON(body []byte, apexDomain string) ([]string, error) {
	var entries []certSpotterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []string
	for _, e := range entries {
		for _, name := range e.DNSNames {
			norm := NormalizeSubdomainCandidate(name, apexDomain)
			if norm != "" && !seen[norm] {
				seen[norm] = true
				results = append(results, norm)
			}
		}
	}
	sort.Strings(results)
	return results, nil
}

func detectWildcardDNS(apexDomain string) map[string]bool {
	wildcardHost := fmt.Sprintf("da-wildcard-probe-%d.%s", time.Now().UnixNano()%1000000, apexDomain)
	ips, _ := lookupSubdomainDNS(wildcardHost)
	if len(ips) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ips))
	for _, ip := range ips {
		m[ip] = true
	}
	return m
}

func matchesWildcardIPs(ips []string, wildcardIPs map[string]bool) bool {
	if len(wildcardIPs) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if wildcardIPs[ip] {
			return true
		}
	}
	return false
}

func lookupSubdomainDNS(hostname string) ([]string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil || len(ips) == 0 {
		return nil, ""
	}

	seen := make(map[string]bool)
	var cleanIPs []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && !seen[ip] {
			seen[ip] = true
			cleanIPs = append(cleanIPs, ip)
		}
	}
	sort.Strings(cleanIPs)

	var cname string
	if cn, err := net.DefaultResolver.LookupCNAME(ctx, hostname); err == nil {
		cleanCN := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cn)), ".")
		if cleanCN != "" && cleanCN != strings.ToLower(hostname) {
			cname = cleanCN
		}
	}
	return cleanIPs, cname
}

