package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"domain-analyzer/analyzer"
)

type TabularFormatter struct{}

func (f *TabularFormatter) Format(w io.Writer, info *analyzer.DomainInfo) error {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)

	// --- DNS SECTION ---
	fmt.Fprintln(tw, "==================================================")
	fmt.Fprintf(tw, "CATEGORY: DNS\n")
	fmt.Fprintln(tw, "==================================================")
	fmt.Fprintf(tw, "Domain\t%s\n", info.Domain)
	if info.ApexDomain != "" && info.ApexDomain != info.Domain {
		fmt.Fprintf(tw, "Apex Domain\t%s\n", info.ApexDomain)
	}
	fmt.Fprintf(tw, "Registrar\t%s\n", info.Registrar)
	fmt.Fprintf(tw, "Domain Expiry\t%s\n", info.ExpiryDate)
	if info.DNS.IPTTL > 0 {
		fmt.Fprintf(tw, "IP Address\t%s (TTL %d)\n", info.DNS.IPAddress, info.DNS.IPTTL)
	} else {
		fmt.Fprintf(tw, "IP Address\t%s\n", info.DNS.IPAddress)
	}
	fmt.Fprintf(tw, "IP Owner\t%s\n", info.DNS.IPOwner)
	if info.DNS.WWWTTL > 0 {
		fmt.Fprintf(tw, "WWW DNS Result\t%s (TTL %d)\n", info.DNS.WWWAddress, info.DNS.WWWTTL)
	} else {
		fmt.Fprintf(tw, "WWW DNS Result\t%s\n", info.DNS.WWWAddress)
	}
	fmt.Fprintf(tw, "Nameservers\t%s\n", strings.Join(info.DNS.Nameservers, ", "))
	fmt.Fprintf(tw, "DNS Providers\t%s\n", strings.Join(info.DNS.NSProviders, ", "))

	if info.DNS.CAARecord != nil {
		fmt.Fprintf(tw, "CAA Issuers\t%s\n", strings.Join(info.DNS.CAARecord.Issuers, ", "))
		fmt.Fprintf(tw, "CAA Wildcards\t%s\n", strings.Join(info.DNS.CAARecord.IssueWildcards, ", "))
		fmt.Fprintf(tw, "CAA Raw\t%s\n", strings.Join(info.DNS.CAARecord.RawRecords, ", "))
	} else {
		fmt.Fprintf(tw, "CAA Records\tNot found\n")
	}

	// --- EMAIL SECTION ---
	fmt.Fprintln(tw, "\n==================================================")
	fmt.Fprintf(tw, "CATEGORY: EMAIL\n")
	fmt.Fprintln(tw, "==================================================")
	fmt.Fprintf(tw, "Mail Providers\t%s\n", strings.Join(info.Email.MailProviders, ", "))

	if info.Email.SPFRecord != nil {
		fmt.Fprintf(tw, "SPF Status\t[%s] %s\n", info.Email.SPFRecord.Status, info.Email.SPFRecord.Description)
		fmt.Fprintf(tw, "SPF Policy\t%s\n", info.Email.SPFRecord.Policy)
		fmt.Fprintf(tw, "SPF Includes\t%s\n", strings.Join(info.Email.SPFRecord.Includes, ", "))
		fmt.Fprintf(tw, "SPF Raw\t%s\n", info.Email.SPFRecord.Raw)
	} else {
		fmt.Fprintf(tw, "SPF Record\tNot found\n")
	}

	if info.Email.DMARCRecord != nil {
		fmt.Fprintf(tw, "DMARC Status\t[%s] %s\n", info.Email.DMARCRecord.Status, info.Email.DMARCRecord.Description)
		fmt.Fprintf(tw, "DMARC Policy\t%s\n", info.Email.DMARCRecord.Policy)
		fmt.Fprintf(tw, "DMARC Reports\t%s\n", strings.Join(info.Email.DMARCRecord.AggregateReports, ", "))
		fmt.Fprintf(tw, "DMARC Raw\t%s\n", info.Email.DMARCRecord.Raw)
	} else {
		fmt.Fprintf(tw, "DMARC Record\tNot found\n")
	}
	// --- SSL/TLS SECTION ---
	fmt.Fprintln(tw, "\n==================================================")
	fmt.Fprintf(tw, "CATEGORY: SSL/TLS\n")
	fmt.Fprintln(tw, "==================================================")
	fmt.Fprintf(tw, "Has TLS\t%v\n", info.TLS.HasTLS)
	if info.TLS.HasTLS {
		fmt.Fprintf(tw, "TLS Provider\t%s\n", info.TLS.TLSIssuer)
		fmt.Fprintf(tw, "TLS Expiry\t%s\n", info.TLS.TLSExpiry)
		fmt.Fprintf(tw, "SAN Domains\t%s\n", strings.Join(info.TLS.SANDomains, ", "))
	}

	// --- WEB SECTION ---
	fmt.Fprintln(tw, "\n==================================================")
	fmt.Fprintf(tw, "CATEGORY: WEB\n")
	fmt.Fprintln(tw, "==================================================")

	techs := []string{}
	for _, t := range info.Web.TechDetails {
		if t.Version != "" {
			techs = append(techs, fmt.Sprintf("%s (%s)", t.Name, t.Version))
		} else {
			techs = append(techs, t.Name)
		}
	}
	if len(techs) == 0 {
		techs = info.Web.TechStack
	}
	fmt.Fprintf(tw, "Tech Stack\t%s\n", strings.Join(techs, ", "))

	if len(info.Web.SecurityHeaders) > 0 {
		// Sort headers for consistent output
		keys := make([]string, 0, len(info.Web.SecurityHeaders))
		for k := range info.Web.SecurityHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(tw, "Header: %s\t%s\n", k, info.Web.SecurityHeaders[k])
		}
	} else {
		fmt.Fprintf(tw, "Security Headers\tNot checked or failed\n")
	}

	// --- WAF SECTION ---
	fmt.Fprintln(tw, "\n==================================================")
	fmt.Fprintf(tw, "CATEGORY: WAF\n")
	fmt.Fprintln(tw, "==================================================")
	fmt.Fprintf(tw, "WAF Detected\t%v\n", info.WAF.Detected)
	if info.WAF.Summary != "" {
		fmt.Fprintf(tw, "WAF Summary\t%s\n", info.WAF.Summary)
	}
	if len(info.WAF.CNAMEs) > 0 {
		fmt.Fprintf(tw, "CNAME Chain\t%s\n", strings.Join(info.WAF.CNAMEs, " -> "))
	}
	if info.WAF.BaselineStatus > 0 || info.WAF.ProbeStatus > 0 {
		fmt.Fprintf(tw, "HTTP Probe Status\tBaseline: %d, WAF Trigger: %d\n", info.WAF.BaselineStatus, info.WAF.ProbeStatus)
	}
	for _, p := range info.WAF.Providers {
		fmt.Fprintf(tw, "Provider [%s]\t%s\n", p.Provider, p.State)
		if len(p.Implementation) > 0 {
			fmt.Fprintf(tw, "  Implementation\t%s\n", strings.Join(p.Implementation, "; "))
		}
		if len(p.Evidence) > 0 {
			fmt.Fprintf(tw, "  Evidence\t%s\n", strings.Join(p.Evidence, ", "))
		}
	}
	for _, note := range info.WAF.OriginNotes {
		fmt.Fprintf(tw, "Downstream Note\t%s\n", note)
	}

	// --- VULNERABILITIES SECTION ---
	if len(info.Vulnerabilities) > 0 {
		fmt.Fprintln(tw, "\n==================================================")
		fmt.Fprintf(tw, "CATEGORY: VULNERABILITIES\n")
		fmt.Fprintln(tw, "==================================================")
		for _, v := range info.Vulnerabilities {
			fmt.Fprintf(tw, "%s [%s]\t%s\n", v.ID, v.Severity, v.Description)
		}
	} else if len(info.Web.TechDetails) > 0 && info.Vulnerabilities == nil {
		// This means we didn't check for vulnerabilities
	} else if len(info.Web.TechDetails) > 0 {
		fmt.Fprintln(tw, "\n==================================================")
		fmt.Fprintf(tw, "CATEGORY: VULNERABILITIES\n")
		fmt.Fprintln(tw, "==================================================")
		fmt.Fprintf(tw, "CVE Check\tNo known vulnerabilities found for detected versions\n")
	}

	fmt.Fprintln(tw, "==================================================")

	return tw.Flush()
}
