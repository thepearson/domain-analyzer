package analyzer

import (
	"fmt"
	"sync"
)

type SPFDetails struct {
	Raw      string   `json:"raw"`
	Policy   string   `json:"policy,omitempty"`   // e.g., "Soft Fail (~all)"
	Includes []string `json:"includes,omitempty"` // e.g., ["_spf.google.com"]
}

type DMARCDetails struct {
	Raw              string   `json:"raw"`
	Policy           string   `json:"policy,omitempty"`            // e.g., "reject"
	AggregateReports []string `json:"aggregate_reports,omitempty"` // e.g., ["mailto:reports@example.com"]
}

type CAADetails struct {
	RawRecords     []string `json:"raw_records"`
	Issuers        []string `json:"issuers,omitempty"`         // e.g., ["pki.goog"]
	IssueWildcards []string `json:"issue_wildcards,omitempty"` // e.g., ["letsencrypt.org"]
}

type DNSInfo struct {
	IPAddress     string      `json:"ip_address,omitempty"`
	IPOwner       string      `json:"ip_owner,omitempty"`
	WWWAddress    string      `json:"www_address,omitempty"`
	Nameservers   []string    `json:"nameservers,omitempty"`
	NSProviders   []string    `json:"ns_providers,omitempty"`
	CAARecord     *CAADetails `json:"caa,omitempty"`
}

type WebInfo struct {
	TechStack       []string          `json:"tech_stack,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
}

type TLSInfo struct {
	HasTLS    bool   `json:"has_tls"`
	TLSIssuer string `json:"tls_issuer,omitempty"`
	TLSExpiry string `json:"tls_expiry,omitempty"`
}

type EmailInfo struct {
	MailProviders []string      `json:"mail_providers,omitempty"`
	SPFRecord     *SPFDetails   `json:"spf,omitempty"`
	DMARCRecord   *DMARCDetails `json:"dmarc,omitempty"`
}

type DomainInfo struct {
	mu         sync.Mutex
	Domain     string `json:"domain"`
	Registrar  string `json:"registrar,omitempty"`
	ExpiryDate string `json:"expiry_date,omitempty"`

	DNS   DNSInfo   `json:"dns"`
	Web   WebInfo   `json:"web"`
	TLS   TLSInfo   `json:"tls"`
	Email EmailInfo `json:"email"`
}

func Analyze(domain string) *DomainInfo {
	info := &DomainInfo{Domain: domain}

	var wg sync.WaitGroup
	wg.Add(9)

	// 1. WHOIS info
	go func() {
		defer wg.Done()
		if err := getWhoisInfo(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching WHOIS info: %v\n", err)
		}
	}()

	// 2. DNS & IP Ownership
	go func() {
		defer wg.Done()
		if err := getIPInfo(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching IP info: %v\n", err)
		}
	}()

	// 3. Nameserver info
	go func() {
		defer wg.Done()
		if err := getNameserverInfo(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching NS info: %v\n", err)
		}
	}()

	// 4. WWW DNS info
	go func() {
		defer wg.Done()
		if err := getWWWInfo(domain, info); err != nil {
			// Don't print warning for missing WWW as it's common
		}
	}()

	// 5. Mail Providers
	go func() {
		defer wg.Done()
		if err := getMailInfo(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching MX records: %v\n", err)
		}
	}()

	// 6. Web info (Tech Stack)
	go func() {
		defer wg.Done()
		if err := getWebInfo(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching web info: %v\n", err)
		}
	}()

	// 7. TLS info
	go func() {
		defer wg.Done()
		if err := getTLSInfo(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching TLS info: %v\n", err)
		}
	}()

	// 8. DNS Security Info (SPF, DMARC, CAA)
	go func() {
		defer wg.Done()
		if err := getDNSSecurityInfo(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching DNS security info: %v\n", err)
		}
	}()

	// 9. HTTP Security Headers
	go func() {
		defer wg.Done()
		if err := getSecurityHeaders(domain, info); err != nil {
			fmt.Printf("Warning: Error fetching security headers: %v\n", err)
		}
	}()

	wg.Wait()
	return info
}

func (info *DomainInfo) Lock() {
	info.mu.Lock()
}

func (info *DomainInfo) Unlock() {
	info.mu.Unlock()
}
