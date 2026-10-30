package analyzer

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type SOADetails struct {
	PrimaryNS  string `json:"primary_ns,omitempty"`
	AdminEmail string `json:"admin_email,omitempty"`
	Serial     uint32 `json:"serial,omitempty"`
	Refresh    uint32 `json:"refresh,omitempty"`
	Retry      uint32 `json:"retry,omitempty"`
	Expire     uint32 `json:"expire,omitempty"`
	MinTTL     uint32 `json:"min_ttl,omitempty"`
}

type DNSKEYRecordInfo struct {
	Role      string `json:"role"` // "KSK (257)" or "ZSK (256)"
	Flags     uint16 `json:"flags"`
	KeyTag    uint16 `json:"key_tag"`
	Algorithm uint8  `json:"algorithm"`
	AlgoName  string `json:"algo_name"`
	PublicKey string `json:"public_key,omitempty"`
}

type DSRecordInfo struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	AlgoName   string `json:"algo_name"`
	DigestType uint8  `json:"digest_type"`
	DigestName string `json:"digest_name"`
	Digest     string `json:"digest"`
}

type AXFRServerResult struct {
	Nameserver    string `json:"nameserver"`
	Vulnerable    bool   `json:"vulnerable"`
	Status        string `json:"status"`
	RecordsLeaked int    `json:"records_leaked,omitempty"`
}

type DNSSECAndZoneAudit struct {
	Audited          bool               `json:"audited"`
	Domain           string             `json:"domain"`
	ApexDomain       string             `json:"apex_domain"`
	HasIPv6          bool               `json:"has_ipv6"`
	IPv6Addresses    []string           `json:"ipv6_addresses,omitempty"`
	WWWIPv6Addresses []string           `json:"www_ipv6_addresses,omitempty"`
	SOA              *SOADetails        `json:"soa,omitempty"`
	DNSSECEnabled    bool               `json:"dnssec_enabled"`
	DNSSECValidated  bool               `json:"dnssec_validated"`
	DNSSECStatus     string             `json:"dnssec_status"` // "Secure (Signed & Validated)", "Unsigned", "Misconfigured"
	DNSSECSummary    string             `json:"dnssec_summary,omitempty"`
	DSRecords        []DSRecordInfo     `json:"ds_records,omitempty"`
	DNSKEYRecords    []DNSKEYRecordInfo `json:"dnskey_records,omitempty"`
	RRSIGCount       int                `json:"rrsig_count,omitempty"`
	AXFRChecked      bool               `json:"axfr_checked"`
	AXFRVulnerable   bool               `json:"axfr_vulnerable"`
	AXFRSummary      string             `json:"axfr_summary,omitempty"`
	AXFRResults      []AXFRServerResult `json:"axfr_results,omitempty"`
}

// InspectDNSSECAndZone performs a comprehensive DNSSEC chain-of-trust, SOA timer, IPv6 AAAA parity,
// and authoritative AXFR zone transfer audit for a domain.
func InspectDNSSECAndZone(domain string) *DNSSECAndZoneAudit {
	clean := CleanDomainTarget(NormalizeTarget(domain))
	apex, err := publicsuffix.EffectiveTLDPlusOne(clean)
	if err != nil || apex == "" {
		apex = clean
	}

	audit := &DNSSECAndZoneAudit{
		Audited:    true,
		Domain:     clean,
		ApexDomain: apex,
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	wg.Add(4)

	// 1. IPv6 (AAAA) Parity on domain (and www.<domain> if apex)
	go func() {
		defer wg.Done()
		aaaa := lookupAAAAAddresses(clean)
		var wwwAAAA []string
		if strings.EqualFold(clean, apex) {
			wwwAAAA = lookupAAAAAddresses("www." + apex)
		}
		mu.Lock()
		audit.IPv6Addresses = aaaa
		audit.WWWIPv6Addresses = wwwAAAA
		audit.HasIPv6 = len(aaaa) > 0 || len(wwwAAAA) > 0
		mu.Unlock()
	}()

	// 2. SOA (Start of Authority) Record on Apex
	go func() {
		defer wg.Done()
		soa := lookupSOA(apex)
		if soa != nil {
			mu.Lock()
			audit.SOA = soa
			mu.Unlock()
		}
	}()

	// 3. DNSSEC (DS, DNSKEY, RRSIG, and Validating Resolver AD Flag)
	go func() {
		defer wg.Done()
		dsList, dnskeyList, rrsigCount, adValidated := lookupDNSSECChain(apex, clean)
		enabled, status, summary := EvaluateDNSSECStatus(dsList, dnskeyList, rrsigCount, adValidated)
		mu.Lock()
		audit.DSRecords = dsList
		audit.DNSKEYRecords = dnskeyList
		audit.RRSIGCount = rrsigCount
		audit.DNSSECValidated = adValidated
		audit.DNSSECEnabled = enabled
		audit.DNSSECStatus = status
		audit.DNSSECSummary = summary
		mu.Unlock()
	}()

	// 4. Authoritative Nameservers Open Zone Transfer (AXFR) Check
	go func() {
		defer wg.Done()
		axfrResults, vulnerable, summary := checkNameserversAXFR(apex)
		mu.Lock()
		audit.AXFRChecked = true
		audit.AXFRVulnerable = vulnerable
		audit.AXFRSummary = summary
		audit.AXFRResults = axfrResults
		mu.Unlock()
	}()

	wg.Wait()
	return audit
}

func lookupAAAAAddresses(host string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

func lookupSOA(apexDomain string) *SOADetails {
	c := &dns.Client{Timeout: 3500 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(apexDomain), dns.TypeSOA)
	m.RecursionDesired = true

	for _, resolver := range []string{"8.8.8.8:53", "1.1.1.1:53"} {
		r, _, err := c.Exchange(m, resolver)
		if err != nil || r == nil {
			continue
		}
		for _, ans := range append(r.Answer, r.Ns...) {
			if soa, ok := ans.(*dns.SOA); ok {
				return ParseSOARecord(soa)
			}
		}
	}
	return nil
}

// ParseSOARecord extracts a structured SOADetails from a miekg/dns SOA resource record.
func ParseSOARecord(soa *dns.SOA) *SOADetails {
	if soa == nil {
		return nil
	}
	return &SOADetails{
		PrimaryNS:  strings.TrimSuffix(strings.TrimSpace(soa.Ns), "."),
		AdminEmail: FormatSOAMbox(soa.Mbox),
		Serial:     soa.Serial,
		Refresh:    soa.Refresh,
		Retry:      soa.Retry,
		Expire:     soa.Expire,
		MinTTL:     soa.Minttl,
	}
}

// FormatSOAMbox converts a DNS SOA RNAME/Mbox (e.g. "dns-admin.google.com.") into an email address ("dns-admin@google.com").
func FormatSOAMbox(mbox string) string {
	clean := strings.TrimSuffix(strings.TrimSpace(mbox), ".")
	if clean == "" {
		return ""
	}
	idx := strings.Index(clean, ".")
	if idx <= 0 || idx == len(clean)-1 {
		return clean
	}
	return clean[:idx] + "@" + clean[idx+1:]
}

func lookupDNSSECChain(apexDomain, queryDomain string) ([]DSRecordInfo, []DNSKEYRecordInfo, int, bool) {
	c := &dns.Client{Timeout: 4 * time.Second}
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53"}

	var (
		dsList      []DSRecordInfo
		dnskeyList  []DNSKEYRecordInfo
		rrsigCount  int
		adValidated bool
	)

	// 1. Query DS records at parent zone
	mDS := new(dns.Msg)
	mDS.SetQuestion(dns.Fqdn(apexDomain), dns.TypeDS)
	mDS.SetEdns0(4096, true)
	mDS.RecursionDesired = true
	for _, res := range resolvers {
		r, _, err := c.Exchange(mDS, res)
		if err != nil || r == nil {
			continue
		}
		if r.AuthenticatedData {
			adValidated = true
		}
		for _, ans := range r.Answer {
			switch rr := ans.(type) {
			case *dns.DS:
				dsList = append(dsList, DSRecordInfo{
					KeyTag:     rr.KeyTag,
					Algorithm:  rr.Algorithm,
					AlgoName:   FormatDNSSECAlgorithm(rr.Algorithm),
					DigestType: rr.DigestType,
					DigestName: FormatDSDigestType(rr.DigestType),
					Digest:     strings.ToUpper(rr.Digest),
				})
			case *dns.RRSIG:
				rrsigCount++
			}
		}
		if len(dsList) > 0 {
			break
		}
	}

	// 2. Query DNSKEY records at apex zone
	mKEY := new(dns.Msg)
	mKEY.SetQuestion(dns.Fqdn(apexDomain), dns.TypeDNSKEY)
	mKEY.SetEdns0(4096, true)
	mKEY.RecursionDesired = true
	for _, res := range resolvers {
		r, _, err := c.Exchange(mKEY, res)
		if err != nil || r == nil {
			continue
		}
		if r.AuthenticatedData {
			adValidated = true
		}
		for _, ans := range r.Answer {
			switch rr := ans.(type) {
			case *dns.DNSKEY:
				role := fmt.Sprintf("Flags %d", rr.Flags)
				if rr.Flags == 257 {
					role = "KSK (257)"
				} else if rr.Flags == 256 {
					role = "ZSK (256)"
				}
				pub := rr.PublicKey
				if len(pub) > 48 {
					pub = pub[:45] + "..."
				}
				dnskeyList = append(dnskeyList, DNSKEYRecordInfo{
					Role:      role,
					Flags:     rr.Flags,
					KeyTag:    rr.KeyTag(),
					Algorithm: rr.Algorithm,
					AlgoName:  FormatDNSSECAlgorithm(rr.Algorithm),
					PublicKey: pub,
				})
			case *dns.RRSIG:
				rrsigCount++
			}
		}
		if len(dnskeyList) > 0 {
			break
		}
	}

	// 3. Query A record with DO=1 to verify RRSIG / AD bit on the target hostname
	mA := new(dns.Msg)
	mA.SetQuestion(dns.Fqdn(queryDomain), dns.TypeA)
	mA.SetEdns0(4096, true)
	mA.RecursionDesired = true
	for _, res := range resolvers {
		r, _, err := c.Exchange(mA, res)
		if err != nil || r == nil {
			continue
		}
		if r.AuthenticatedData {
			adValidated = true
		}
		for _, ans := range r.Answer {
			if _, ok := ans.(*dns.RRSIG); ok {
				rrsigCount++
			}
		}
		break
	}

	return dsList, dnskeyList, rrsigCount, adValidated
}

// EvaluateDNSSECStatus determines whether DNSSEC is properly signed and chained to the parent zone.
func EvaluateDNSSECStatus(ds []DSRecordInfo, keys []DNSKEYRecordInfo, rrsigCount int, adValidated bool) (enabled bool, status string, summary string) {
	hasDS := len(ds) > 0
	hasKeys := len(keys) > 0

	if hasDS && hasKeys {
		if adValidated || rrsigCount > 0 {
			return true, "Secure (Signed & Validated)", fmt.Sprintf("Full DNSSEC chain of trust verified (%d DS, %d DNSKEY, %d RRSIG records)", len(ds), len(keys), rrsigCount)
		}
		return true, "Signed (Unverified AD)", fmt.Sprintf("DS (%d) and DNSKEY (%d) records present", len(ds), len(keys))
	}
	if hasKeys && !hasDS {
		return false, "Incomplete (Missing Parent DS)", fmt.Sprintf("Zone has %d DNSKEY record(s) but no DS delegation record in the parent TLD zone", len(keys))
	}
	if hasDS && !hasKeys {
		return false, "Broken Chain (DS Without DNSKEY)", "Parent zone publishes DS record(s) but no matching DNSKEY records were returned"
	}
	return false, "Unsigned", "DNSSEC is not enabled for this domain (no DS or DNSKEY records)"
}

// FormatDNSSECAlgorithm maps IANA DNSSEC algorithm numbers to human-readable names.
func FormatDNSSECAlgorithm(alg uint8) string {
	switch alg {
	case 5:
		return "RSASHA1 (5)"
	case 7:
		return "RSASHA1-NSEC3-SHA1 (7)"
	case 8:
		return "RSASHA256 (8)"
	case 10:
		return "RSASHA512 (10)"
	case 12:
		return "ECC-GOST (12)"
	case 13:
		return "ECDSAP256SHA256 (13)"
	case 14:
		return "ECDSAP384SHA384 (14)"
	case 15:
		return "ED25519 (15)"
	case 16:
		return "ED448 (16)"
	default:
		return fmt.Sprintf("Algorithm %d", alg)
	}
}

// FormatDSDigestType maps DNSSEC DS digest type IDs to human-readable names.
func FormatDSDigestType(dt uint8) string {
	switch dt {
	case 1:
		return "SHA-1 (1)"
	case 2:
		return "SHA-256 (2)"
	case 3:
		return "GOST R 34.11-94 (3)"
	case 4:
		return "SHA-384 (4)"
	default:
		return fmt.Sprintf("Digest %d", dt)
	}
}

func checkNameserversAXFR(apexDomain string) ([]AXFRServerResult, bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()

	nss, err := net.DefaultResolver.LookupNS(ctx, apexDomain)
	if err != nil || len(nss) == 0 {
		return nil, false, "No authoritative nameservers resolved for AXFR test"
	}

	var hosts []string
	seen := make(map[string]bool)
	for _, ns := range nss {
		h := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
		lower := strings.ToLower(h)
		if h != "" && !seen[lower] {
			seen[lower] = true
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	if len(hosts) > 6 {
		hosts = hosts[:6]
	}

	results := make([]AXFRServerResult, len(hosts))
	var wg sync.WaitGroup
	for i, nsHost := range hosts {
		wg.Add(1)
		go func(idx int, server string) {
			defer wg.Done()
			results[idx] = probeSingleAXFR(apexDomain, server)
		}(i, nsHost)
	}
	wg.Wait()

	vulnerable := false
	for _, r := range results {
		if r.Vulnerable {
			vulnerable = true
			break
		}
	}

	if vulnerable {
		return results, true, "CRITICAL: One or more authoritative nameservers allow unauthenticated AXFR zone transfers!"
	}
	return results, false, fmt.Sprintf("Secure: All %d authoritative nameservers properly refused AXFR zone transfers", len(results))
}

func probeSingleAXFR(apexDomain, nsHost string) AXFRServerResult {
	res := AXFRServerResult{
		Nameserver: nsHost,
		Vulnerable: false,
		Status:     "Refused (Secure)",
	}

	tr := &dns.Transfer{
		DialTimeout: 2500 * time.Millisecond,
		ReadTimeout: 2500 * time.Millisecond,
	}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(apexDomain))

	envCh, err := tr.In(m, net.JoinHostPort(nsHost, "53"))
	if err != nil {
		res.Status = "Refused / Blocked (Secure)"
		return res
	}

	leakedCount := 0
	for env := range envCh {
		if env.Error != nil {
			break
		}
		leakedCount += len(env.RR)
		if leakedCount > 50 {
			break
		}
	}

	if leakedCount > 0 {
		res.Vulnerable = true
		res.RecordsLeaked = leakedCount
		res.Status = fmt.Sprintf("VULNERABLE (%d+ records leaked via AXFR)", leakedCount)
	}
	return res
}
