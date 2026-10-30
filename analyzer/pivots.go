package analyzer

import (
	"strings"
)

type TargetType string

const (
	TargetTypeDomain TargetType = "domain"
	TargetTypeIP     TargetType = "ip"
)

type PivotTarget struct {
	Target string     `json:"target"`
	Type   TargetType `json:"type"`
	Reason string     `json:"reason"` // e.g., "Apex Domain", "A Record", "WWW Record", "CNAME", "TLS SAN", "Nameserver", "SPF Include", "PTR Record"
}

// CleanDomainTarget normalizes a discovered domain/hostname (strips wildcard "*. " and trailing dots).
func CleanDomainTarget(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, ".")
	return strings.ToLower(d)
}

// ExtractDomainPivots extracts all actionable domain and IP targets discovered during a domain scan.
func ExtractDomainPivots(info *DomainInfo) []PivotTarget {
	if info == nil {
		return nil
	}

	var pivots []PivotTarget
	seen := make(map[string]bool)
	selfDomain := CleanDomainTarget(info.Domain)
	if selfDomain != "" {
		seen["domain:"+selfDomain] = true
	}

	addDomain := func(raw string, reason string) {
		clean := CleanDomainTarget(raw)
		if clean == "" || !strings.Contains(clean, ".") || IsIPAddress(clean) {
			return
		}
		key := "domain:" + clean
		if seen[key] {
			return
		}
		seen[key] = true
		pivots = append(pivots, PivotTarget{
			Target: clean,
			Type:   TargetTypeDomain,
			Reason: reason,
		})
	}

	addIP := func(raw string, reason string) {
		clean := strings.TrimSpace(raw)
		if clean == "" || !IsIPAddress(clean) {
			return
		}
		key := "ip:" + clean
		if seen[key] {
			return
		}
		seen[key] = true
		pivots = append(pivots, PivotTarget{
			Target: clean,
			Type:   TargetTypeIP,
			Reason: reason,
		})
	}

	// 1. Apex Domain (if different from scanned subdomain)
	addDomain(info.ApexDomain, "Apex Domain")

	// 2. DNS IP addresses
	addIP(info.DNS.IPAddress, "A Record")
	addIP(info.DNS.WWWAddress, "WWW Record")

	// 3. CNAME chain
	for _, cname := range info.WAF.CNAMEs {
		addDomain(cname, "CNAME")
	}

	// 4. TLS Subject Alternative Names
	for _, san := range info.TLS.SANDomains {
		addDomain(san, "TLS SAN")
	}

	// 5. SPF Includes
	if info.Email.SPFRecord != nil {
		for _, inc := range info.Email.SPFRecord.Includes {
			addDomain(inc, "SPF Include")
		}
	}

	// 6. Nameservers
	for _, ns := range info.DNS.Nameservers {
		addDomain(ns, "Nameserver")
	}

	// 7. Discovered Subdomains & Resolved IPs
	if info.Subdomains != nil {
		for _, sub := range info.Subdomains.Subdomains {
			addDomain(sub.Subdomain, "Subdomain")
			for _, ip := range sub.IPAddresses {
				addIP(ip, "Subdomain IP ("+sub.Subdomain+")")
			}
		}
	}

	// 8. Website Metadata & Sitemap Hostnames
	if info.Metadata != nil {
		for _, h := range info.Metadata.Sitemap.DiscoveredHosts {
			addDomain(h, "Sitemap Host")
		}
	}

	// 9. HTTP Redirect Chain Hostnames
	if info.HTTPTrace != nil {
		for _, h := range info.HTTPTrace.DiscoveredHosts {
			addDomain(h, "HTTP Redirect")
		}
	}

	return pivots
}

// ExtractIPPivots extracts all actionable domain targets discovered during an IP scan.
func ExtractIPPivots(info *IPInfo) []PivotTarget {
	if info == nil {
		return nil
	}

	var pivots []PivotTarget
	seen := make(map[string]bool)

	addDomain := func(raw string, reason string) {
		clean := CleanDomainTarget(raw)
		if clean == "" || !strings.Contains(clean, ".") || IsIPAddress(clean) {
			return
		}
		key := "domain:" + clean
		if seen[key] {
			return
		}
		seen[key] = true
		pivots = append(pivots, PivotTarget{
			Target: clean,
			Type:   TargetTypeDomain,
			Reason: reason,
		})
	}

	for _, ptr := range info.PTRRecords {
		addDomain(ptr, "PTR Record")
	}

	for _, san := range info.TLS.SANDomains {
		addDomain(san, "TLS SAN")
	}

	for _, cname := range info.WAF.CNAMEs {
		addDomain(cname, "CNAME")
	}

	return pivots
}
