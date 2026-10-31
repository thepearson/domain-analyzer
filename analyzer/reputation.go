package analyzer

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

type DNSBLEntry struct {
	Provider    string   `json:"provider"`
	Zone        string   `json:"zone"`
	Category    string   `json:"category"` // "IP RBL" or "Domain URI RBL"
	Target      string   `json:"target"`
	Listed      bool     `json:"listed"`
	ReturnCodes []string `json:"return_codes,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

type ReputationLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type ReputationResult struct {
	Checked       bool             `json:"checked"`
	Target        string           `json:"target"`
	ResolvedIP    string           `json:"resolved_ip,omitempty"`
	Status        string           `json:"status"` // "Clean (0 Listed)" or "Listed on N Blacklist(s)"
	TotalChecked  int              `json:"total_checked"`
	ListedCount   int              `json:"listed_count"`
	Entries       []DNSBLEntry     `json:"entries,omitempty"`
	ExternalLinks []ReputationLink `json:"external_links,omitempty"`
}

type dnsblProviderSpec struct {
	Name     string
	Zone     string
	Category string // "IP RBL" or "Domain URI RBL"
}

var ipDNSBLProviders = []dnsblProviderSpec{
	{Name: "Spamhaus ZEN", Zone: "zen.spamhaus.org", Category: "IP RBL"},
	{Name: "SpamCop", Zone: "bl.spamcop.net", Category: "IP RBL"},
	{Name: "Barracuda RBL", Zone: "b.barracudacentral.org", Category: "IP RBL"},
	{Name: "SORBS Aggregate", Zone: "dnsbl.sorbs.net", Category: "IP RBL"},
	{Name: "UCEPROTECT L1", Zone: "dnsbl-1.uceprotect.net", Category: "IP RBL"},
	{Name: "PSBL Surriel", Zone: "psbl.surriel.com", Category: "IP RBL"},
	{Name: "DroneBL (Botnet/Abuse)", Zone: "dnsbl.dronebl.org", Category: "IP RBL"},
	{Name: "Spam Eating Monkey IP", Zone: "bl.spameatingmonkey.net", Category: "IP RBL"},
}

var domainDNSBLProviders = []dnsblProviderSpec{
	{Name: "Spamhaus DBL", Zone: "dbl.spamhaus.org", Category: "Domain URI RBL"},
	{Name: "SURBL Multi", Zone: "multi.surbl.org", Category: "Domain URI RBL"},
	{Name: "URIBL Black", Zone: "black.uribl.com", Category: "Domain URI RBL"},
	{Name: "Spam Eating Monkey URI", Zone: "uribl.spameatingmonkey.net", Category: "Domain URI RBL"},
}

// CheckReputation queries DNS-based spam, malware, phishing, and abuse blocklists (DNSBL / DBL / URIBL)
// for a domain or IP address.
func CheckReputation(target string) *ReputationResult {
	clean := NormalizeTarget(target)
	isIP := IsIPAddress(clean)
	if !isIP {
		clean = CleanDomainTarget(clean)
	}

	res := &ReputationResult{
		Checked:       true,
		Target:        clean,
		ExternalLinks: BuildExternalReputationLinks(clean, isIP),
	}

	type checkJob struct {
		spec   dnsblProviderSpec
		qname  string
		target string
	}

	var jobs []checkJob

	if isIP {
		res.ResolvedIP = clean
		if rev, ok := ReverseIPv4ForDNSBL(clean); ok {
			for _, p := range ipDNSBLProviders {
				jobs = append(jobs, checkJob{
					spec:   p,
					qname:  rev + "." + p.Zone,
					target: clean,
				})
			}
		}
	} else {
		apex, err := publicsuffix.EffectiveTLDPlusOne(clean)
		if err != nil || apex == "" {
			apex = clean
		}
		for _, p := range domainDNSBLProviders {
			jobs = append(jobs, checkJob{
				spec:   p,
				qname:  apex + "." + p.Zone,
				target: apex,
			})
		}

		// Also resolve IPv4 of the domain to check IP RBLs
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", clean); err == nil && len(ips) > 0 {
			ipStr := ips[0].String()
			res.ResolvedIP = ipStr
			if rev, ok := ReverseIPv4ForDNSBL(ipStr); ok {
				for _, p := range ipDNSBLProviders {
					jobs = append(jobs, checkJob{
						spec:   p,
						qname:  rev + "." + p.Zone,
						target: ipStr,
					})
				}
			}
		}
		cancel()
	}

	entries := make([]DNSBLEntry, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for i, jb := range jobs {
		wg.Add(1)
		go func(idx int, job checkJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			entries[idx] = querySingleDNSBL(job.spec, job.qname, job.target)
		}(i, jb)
	}
	wg.Wait()

	listedCount := 0
	for _, e := range entries {
		if e.Listed {
			listedCount++
		}
	}

	res.Entries = entries
	res.TotalChecked = len(entries)
	res.ListedCount = listedCount
	if listedCount == 0 {
		res.Status = fmt.Sprintf("Clean (0/%d Blacklists)", len(entries))
	} else {
		res.Status = fmt.Sprintf("LISTED (%d/%d Blacklists)", listedCount, len(entries))
	}

	return res
}

func querySingleDNSBL(spec dnsblProviderSpec, qname string, target string) DNSBLEntry {
	entry := DNSBLEntry{
		Provider: spec.Name,
		Zone:     spec.Zone,
		Category: spec.Category,
		Target:   target,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, qname)
	if err != nil || len(addrs) == 0 {
		return entry
	}

	var txts []string
	txtCtx, txtCancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	if t, err := net.DefaultResolver.LookupTXT(txtCtx, qname); err == nil {
		txts = t
	}
	txtCancel()

	listed, validCodes, reason := IsValidDNSBLListing(spec.Zone, addrs, txts)
	if listed {
		entry.Listed = true
		entry.ReturnCodes = validCodes
		entry.Reason = reason
	}
	return entry
}

// ReverseIPv4ForDNSBL reverses the 4 octets of an IPv4 address for DNSBL queries (e.g. "93.184.216.34" -> "34.216.184.93").
func ReverseIPv4ForDNSBL(ipStr string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0]), true
}

// IsValidDNSBLListing validates DNSBL A-record return codes and TXT explanations,
// filtering out public DNS resolver error/rate-limit codes (such as 127.255.255.252/254/255).
func IsValidDNSBLListing(zone string, returnIPs []string, txtRecords []string) (listed bool, validCodes []string, reason string) {
	combinedTXT := strings.TrimSpace(strings.Join(txtRecords, "; "))
	lowerTXT := strings.ToLower(combinedTXT)

	// Filter out administrative / open-resolver refusal messages
	if strings.Contains(lowerTXT, "query refused") ||
		strings.Contains(lowerTXT, "open resolver") ||
		strings.Contains(lowerTXT, "excessive number of queries") {
		return false, nil, ""
	}

	lowerZone := strings.ToLower(zone)
	for _, rawIP := range returnIPs {
		ip := strings.TrimSpace(rawIP)
		// Standard DNSBL responses MUST be in 127.0.0.0/8, excluding 127.255.255.* administrative error codes
		if !strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "127.255.255.") {
			continue
		}
		// URIBL returns 127.0.0.1 when blocking public DNS resolvers
		if strings.Contains(lowerZone, "uribl.com") && ip == "127.0.0.1" {
			continue
		}
		// Spamhaus ZEN 127.0.0.10 and 127.0.0.11 indicate Policy Block List (dynamic ISP range, not active spam/malware)
		if lowerZone == "zen.spamhaus.org" && (ip == "127.0.0.10" || ip == "127.0.0.11") {
			continue
		}
		validCodes = append(validCodes, ip)
	}

	if len(validCodes) == 0 {
		return false, nil, ""
	}

	if combinedTXT != "" {
		if len(combinedTXT) > 160 {
			combinedTXT = combinedTXT[:157] + "..."
		}
		return true, validCodes, combinedTXT
	}
	return true, validCodes, "Listed (" + strings.Join(validCodes, ", ") + ")"
}

// BuildExternalReputationLinks returns one-click threat intelligence & reputation lookup URLs for a domain or IP.
func BuildExternalReputationLinks(target string, isIP bool) []ReputationLink {
	clean := strings.TrimSpace(target)
	if clean == "" {
		return nil
	}
	esc := url.QueryEscape(clean)

	if isIP {
		return []ReputationLink{
			{Label: "VirusTotal IP ↗", URL: "https://www.virustotal.com/gui/ip-address/" + url.PathEscape(clean)},
			{Label: "AbuseIPDB ↗", URL: "https://www.abuseipdb.com/check/" + url.PathEscape(clean)},
			{Label: "Spamhaus Checker ↗", URL: "https://check.spamhaus.org/results/?query=" + esc},
			{Label: "Cisco Talos ↗", URL: "https://talosintelligence.com/reputation_center/lookup?search=" + esc},
		}
	}

	return []ReputationLink{
		{Label: "VirusTotal Domain ↗", URL: "https://www.virustotal.com/gui/domain/" + url.PathEscape(clean)},
		{Label: "Google Safe Browsing ↗", URL: "https://transparencyreport.google.com/safe-browsing/search?url=" + esc},
		{Label: "Spamhaus Checker ↗", URL: "https://check.spamhaus.org/results/?query=" + esc},
		{Label: "Cisco Talos ↗", URL: "https://talosintelligence.com/reputation_center/lookup?search=" + esc},
	}
}

