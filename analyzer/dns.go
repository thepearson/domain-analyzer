package analyzer

import (
	"fmt"
	"net"
	"strings"

	"github.com/likexian/whois"
	"github.com/miekg/dns"
)

func getDNSSecurityInfo(domain string, info *DomainInfo) error {
	// SPF
	txts, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") {
				info.Lock()
				info.Email.SPFRecord = ParseSPF(txt)
				info.Unlock()
				break
			}
		}
	}

	// DMARC
	dmarcTxts, err := net.LookupTXT("_dmarc." + domain)
	if err == nil {
		for _, txt := range dmarcTxts {
			if strings.HasPrefix(txt, "v=DMARC1") {
				info.Lock()
				info.Email.DMARCRecord = ParseDMARC(txt)
				info.Unlock()
				break
			}
		}
	}

	// CAA
	caaDetails, err := lookupCAA(domain)
	if err == nil && caaDetails != nil {
		info.Lock()
		info.DNS.CAARecord = caaDetails
		info.Unlock()
	}

	return nil
}

func ParseSPF(raw string) *SPFDetails {
	details := &SPFDetails{Raw: raw, Status: "Warning", Description: "No policy enforcement found"}
	parts := strings.Fields(raw)

	for _, part := range parts {
		if strings.HasPrefix(part, "include:") {
			details.Includes = append(details.Includes, strings.TrimPrefix(part, "include:"))
		} else if part == "-all" {
			details.Policy = "Fail (-all)"
			details.Status = "Secure"
			details.Description = "Strict enforcement; unauthorized emails are rejected."
		} else if part == "~all" {
			details.Policy = "Soft Fail (~all)"
			details.Status = "Warning"
			details.Description = "Partial enforcement; unauthorized emails may still be delivered to spam."
		} else if part == "?all" {
			details.Policy = "Neutral (?all)"
			details.Status = "Warning"
			details.Description = "No enforcement; policy is effectively disabled."
		} else if part == "+all" {
			details.Policy = "Pass (+all)"
			details.Status = "Critical"
			details.Description = "Highly insecure; explicitly allows ANY server to send email on your behalf."
		}
	}
	return details
}

func ParseDMARC(raw string) *DMARCDetails {
	details := &DMARCDetails{Raw: raw, Status: "Warning", Description: "DMARC record exists but may not be enforcing"}
	parts := strings.Split(raw, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			p := strings.TrimPrefix(part, "p=")
			details.Policy = p
			switch p {
			case "reject":
				details.Status = "Secure"
				details.Description = "Maximum protection; unauthorized emails are rejected by receivers."
			case "quarantine":
				details.Status = "Secure"
				details.Description = "Strong protection; unauthorized emails are sent to the recipient's spam folder."
			case "none":
				details.Status = "Warning"
				details.Description = "Monitoring mode only; no enforcement against spoofing."
			}
		} else if strings.HasPrefix(part, "rua=") {
			reports := strings.Split(strings.TrimPrefix(part, "rua="), ",")
			for _, r := range reports {
				details.AggregateReports = append(details.AggregateReports, strings.TrimSpace(r))
			}
		}
	}
	return details
}

func lookupCAA(domain string) (*CAADetails, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	details := &CAADetails{}
	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			raw := fmt.Sprintf("%d %s %q", caa.Flag, caa.Tag, caa.Value)
			details.RawRecords = append(details.RawRecords, raw)
			if caa.Tag == "issue" {
				details.Issuers = append(details.Issuers, caa.Value)
			} else if caa.Tag == "issuewild" {
				details.IssueWildcards = append(details.IssueWildcards, caa.Value)
			}
		}
	}
	if len(details.RawRecords) == 0 {
		return nil, nil
	}
	return details, nil
}

func getNameserverInfo(domain string, info *DomainInfo) error {
	nss, err := net.LookupNS(domain)
	if err != nil {
		return err
	}

	var hosts []string
	for _, ns := range nss {
		hosts = append(hosts, ns.Host)
	}

	info.Lock()
	info.DNS.Nameservers = hosts
	info.DNS.NSProviders = IdentifyNSProviders(hosts)
	info.Unlock()

	return nil
}

func getWWWInfo(domain string, info *DomainInfo) error {
	wwwDomain := "www." + domain
	ips, err := net.LookupIP(wwwDomain)
	if err != nil || len(ips) == 0 {
		return err
	}

	info.Lock()
	info.DNS.WWWAddress = ips[0].String()
	info.Unlock()
	return nil
}

func IdentifyNSProviders(hosts []string) []string {
	knownProviders := []struct {
		Name    string
		Pattern string
	}{
		{"Cloudflare", "cloudflare.com"},
		{"AWS Route 53", "awsdns"},
		{"Google Cloud DNS", "googledomains.com"},
		{"Google Cloud DNS", "google.com"},
		{"Azure DNS", "azure-dns"},
		{"DigitalOcean", "digitalocean.com"},
		{"GoDaddy", "domaincontrol.com"},
		{"Namecheap", "registrar-servers.com"},
		{"Linode", "linode.com"},
		{"Vultr", "vultr.com"},
	}

	providers := make(map[string]bool)
	for _, host := range hosts {
		host = strings.ToLower(host)
		for _, kp := range knownProviders {
			if strings.Contains(host, kp.Pattern) {
				providers[kp.Name] = true
			}
		}
	}

	result := []string{}
	for p := range providers {
		result = append(result, p)
	}
	return result
}

func getMailInfo(domain string, info *DomainInfo) error {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return err
	}

	hosts := []string{}
	for _, mx := range mxs {
		hosts = append(hosts, mx.Host)
	}

	info.Lock()
	info.Email.MailProviders = IdentifyMailProviders(hosts)
	info.Unlock()
	return nil
}

func IdentifyMailProviders(hosts []string) []string {
	knownProviders := []struct {
		Name    string
		Pattern string
	}{
		{"Google Workspace", "google.com"},
		{"Google Workspace", "googlemail.com"},
		{"Microsoft Outlook/Office 365", "outlook.com"},
		{"Zoho Mail", "zoho.com"},
		{"Proton Mail", "protonmail.ch"},
		{"Proton Mail", "pm.me"},
		{"Fastmail", "fastmail.com"},
		{"GoDaddy Mail", "secureserver.net"},
		{"Mimecast", "mimecast.com"},
		{"Proofpoint", "pphosted.com"},
	}

	providers := make(map[string]bool)
	for _, host := range hosts {
		host = strings.ToLower(host)
		for _, kp := range knownProviders {
			if strings.Contains(host, kp.Pattern) {
				providers[kp.Name] = true
			}
		}
	}

	result := []string{}
	for p := range providers {
		result = append(result, p)
	}

	if len(result) == 0 && len(hosts) > 0 {
		result = append(result, "Generic/Other (MX records found)")
	}

	return result
}

func getIPInfo(domain string, info *DomainInfo) error {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return err
	}

	info.Lock()
	info.DNS.IPAddress = ips[0].String()
	info.Unlock()

	// Find IP owner via WHOIS
	result, err := whois.Whois(ips[0].String())
	if err == nil {
		owner := ParseIPOwner(result)
		if owner != "" {
			info.Lock()
			info.DNS.IPOwner = owner
			info.Unlock()
		}
	}

	return nil
}

func ParseIPOwner(whoisOutput string) string {
	lines := strings.Split(whoisOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "orgname:") ||
			strings.HasPrefix(lowerLine, "organization:") ||
			strings.HasPrefix(lowerLine, "descr:") ||
			strings.HasPrefix(lowerLine, "owner:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
