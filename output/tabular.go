package output

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"domain-analyzer/analyzer"
)

type TabularFormatter struct{}

func (f *TabularFormatter) Format(info *analyzer.DomainInfo) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)

	// --- DNS SECTION ---
	fmt.Fprintln(w, "==================================================")
	fmt.Fprintf(w, "CATEGORY: DNS\n")
	fmt.Fprintln(w, "==================================================")
	fmt.Fprintf(w, "Domain\t%s\n", info.Domain)
	fmt.Fprintf(w, "Registrar\t%s\n", info.Registrar)
	fmt.Fprintf(w, "Domain Expiry\t%s\n", info.ExpiryDate)
	fmt.Fprintf(w, "IP Address\t%s\n", info.DNS.IPAddress)
	fmt.Fprintf(w, "IP Owner\t%s\n", info.DNS.IPOwner)
	fmt.Fprintf(w, "WWW DNS Result\t%s\n", info.DNS.WWWAddress)
	fmt.Fprintf(w, "Nameservers\t%s\n", strings.Join(info.DNS.Nameservers, ", "))
	fmt.Fprintf(w, "DNS Providers\t%s\n", strings.Join(info.DNS.NSProviders, ", "))

	if info.DNS.CAARecord != nil {
		fmt.Fprintf(w, "CAA Issuers\t%s\n", strings.Join(info.DNS.CAARecord.Issuers, ", "))
		fmt.Fprintf(w, "CAA Wildcards\t%s\n", strings.Join(info.DNS.CAARecord.IssueWildcards, ", "))
		fmt.Fprintf(w, "CAA Raw\t%s\n", strings.Join(info.DNS.CAARecord.RawRecords, ", "))
	} else {
		fmt.Fprintf(w, "CAA Records\tNot found\n")
	}

	// --- EMAIL SECTION ---
	fmt.Fprintln(w, "\n==================================================")
	fmt.Fprintf(w, "CATEGORY: EMAIL\n")
	fmt.Fprintln(w, "==================================================")
	fmt.Fprintf(w, "Mail Providers\t%s\n", strings.Join(info.Email.MailProviders, ", "))

	if info.Email.SPFRecord != nil {
		fmt.Fprintf(w, "SPF Status\t[%s] %s\n", info.Email.SPFRecord.Status, info.Email.SPFRecord.Description)
		fmt.Fprintf(w, "SPF Policy\t%s\n", info.Email.SPFRecord.Policy)
		fmt.Fprintf(w, "SPF Includes\t%s\n", strings.Join(info.Email.SPFRecord.Includes, ", "))
		fmt.Fprintf(w, "SPF Raw\t%s\n", info.Email.SPFRecord.Raw)
	} else {
		fmt.Fprintf(w, "SPF Record\tNot found\n")
	}

	if info.Email.DMARCRecord != nil {
		fmt.Fprintf(w, "DMARC Status\t[%s] %s\n", info.Email.DMARCRecord.Status, info.Email.DMARCRecord.Description)
		fmt.Fprintf(w, "DMARC Policy\t%s\n", info.Email.DMARCRecord.Policy)
		fmt.Fprintf(w, "DMARC Reports\t%s\n", strings.Join(info.Email.DMARCRecord.AggregateReports, ", "))
		fmt.Fprintf(w, "DMARC Raw\t%s\n", info.Email.DMARCRecord.Raw)
	} else {
		fmt.Fprintf(w, "DMARC Record\tNot found\n")
	}
	// --- SSL/TLS SECTION ---
	fmt.Fprintln(w, "\n==================================================")
	fmt.Fprintf(w, "CATEGORY: SSL/TLS\n")
	fmt.Fprintln(w, "==================================================")
	fmt.Fprintf(w, "Has TLS\t%v\n", info.TLS.HasTLS)
	if info.TLS.HasTLS {
		fmt.Fprintf(w, "TLS Provider\t%s\n", info.TLS.TLSIssuer)
		fmt.Fprintf(w, "TLS Expiry\t%s\n", info.TLS.TLSExpiry)
		fmt.Fprintf(w, "SAN Domains\t%s\n", strings.Join(info.TLS.SANDomains, ", "))
	}

	// --- WEB SECTION ---
	fmt.Fprintln(w, "\n==================================================")
	fmt.Fprintf(w, "CATEGORY: WEB\n")
	fmt.Fprintln(w, "==================================================")

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
	fmt.Fprintf(w, "Tech Stack\t%s\n", strings.Join(techs, ", "))

	if len(info.Web.SecurityHeaders) > 0 {
		// Sort headers for consistent output
		keys := make([]string, 0, len(info.Web.SecurityHeaders))
		for k := range info.Web.SecurityHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "Header: %s\t%s\n", k, info.Web.SecurityHeaders[k])
		}
	} else {
		fmt.Fprintf(w, "Security Headers\tNot checked or failed\n")
	}

	// --- VULNERABILITIES SECTION ---
	if len(info.Vulnerabilities) > 0 {
		fmt.Fprintln(w, "\n==================================================")
		fmt.Fprintf(w, "CATEGORY: VULNERABILITIES\n")
		fmt.Fprintln(w, "==================================================")
		for _, v := range info.Vulnerabilities {
			fmt.Fprintf(w, "%s [%s]\t%s\n", v.ID, v.Severity, v.Description)
		}
	} else if len(info.Web.TechDetails) > 0 && info.Vulnerabilities == nil {
		// This means we didn't check for vulnerabilities
	} else if len(info.Web.TechDetails) > 0 {
		fmt.Fprintln(w, "\n==================================================")
		fmt.Fprintf(w, "CATEGORY: VULNERABILITIES\n")
		fmt.Fprintln(w, "==================================================")
		fmt.Fprintf(w, "CVE Check\tNo known vulnerabilities found for detected versions\n")
	}

	fmt.Fprintln(w, "==================================================")

	return w.Flush()
}
