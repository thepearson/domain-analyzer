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

	if info.ZoneAudit != nil {
		if len(info.ZoneAudit.IPv6Addresses) > 0 {
			fmt.Fprintf(tw, "IPv6 (AAAA)\t%s\n", strings.Join(info.ZoneAudit.IPv6Addresses, ", "))
		} else {
			fmt.Fprintf(tw, "IPv6 (AAAA)\tNone (IPv4 only)\n")
		}
		if info.ZoneAudit.SOA != nil {
			fmt.Fprintf(tw, "SOA Primary NS\t%s (Admin: %s, Serial: %d)\n",
				info.ZoneAudit.SOA.PrimaryNS, info.ZoneAudit.SOA.AdminEmail, info.ZoneAudit.SOA.Serial)
		}
		fmt.Fprintf(tw, "DNSSEC Status\t[%s] %s\n", info.ZoneAudit.DNSSECStatus, info.ZoneAudit.DNSSECSummary)
		if info.ZoneAudit.AXFRChecked {
			fmt.Fprintf(tw, "Zone Transfer (AXFR)\t%s\n", info.ZoneAudit.AXFRSummary)
		}
	}

	// --- EMAIL SECTION ---
	fmt.Fprintln(tw, "\n==================================================")
	fmt.Fprintf(tw, "CATEGORY: EMAIL\n")
	fmt.Fprintln(tw, "==================================================")
	fmt.Fprintf(tw, "Mail Providers\t%s\n", strings.Join(info.Email.MailProviders, ", "))
	if len(info.Email.MXRecords) > 0 {
		fmt.Fprintf(tw, "MX Records\t%s\n", strings.Join(info.Email.MXRecords, ", "))
	}

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

	if len(info.Email.DKIMRecords) > 0 {
		var dkimSummaries []string
		for _, d := range info.Email.DKIMRecords {
			label := fmt.Sprintf("%s (%s)", d.Selector, strings.ToUpper(d.KeyType))
			if d.CNAME != "" {
				label += " -> " + d.CNAME
			}
			dkimSummaries = append(dkimSummaries, label)
		}
		fmt.Fprintf(tw, "DKIM Selectors\t%s\n", strings.Join(dkimSummaries, ", "))
	} else {
		fmt.Fprintf(tw, "DKIM Selectors\tNone discovered on common selectors\n")
	}

	if info.Email.MTASTS != nil && info.Email.MTASTS.Found {
		fmt.Fprintf(tw, "MTA-STS\tMode: %s (Max-Age: %s, ID: %s)\n", info.Email.MTASTS.Mode, info.Email.MTASTS.MaxAge, info.Email.MTASTS.ID)
	} else {
		fmt.Fprintf(tw, "MTA-STS\tNot configured\n")
	}

	if info.Email.TLSRPT != nil && info.Email.TLSRPT.Found {
		fmt.Fprintf(tw, "SMTP TLS-RPT\t%s\n", strings.Join(info.Email.TLSRPT.Endpoints, ", "))
	} else {
		fmt.Fprintf(tw, "SMTP TLS-RPT\tNot configured\n")
	}

	if info.Email.BIMI != nil && info.Email.BIMI.Found {
		fmt.Fprintf(tw, "BIMI Brand Logo\t%s (VMC: %s)\n", info.Email.BIMI.LogoURL, info.Email.BIMI.AuthorityURL)
	} else {
		fmt.Fprintf(tw, "BIMI Record\tNot configured\n")
	}
	// --- SSL/TLS SECTION ---
	fmt.Fprintln(tw, "\n==================================================")
	fmt.Fprintf(tw, "CATEGORY: SSL/TLS\n")
	fmt.Fprintln(tw, "==================================================")
	fmt.Fprintf(tw, "Has TLS\t%v\n", info.TLS.HasTLS)
	if info.TLS.HasTLS {
		if info.TLS.Grade != "" {
			fmt.Fprintf(tw, "TLS Security Grade\t[%s] %s\n", info.TLS.Grade, info.TLS.GradeSummary)
		}
		if info.TLS.NegotiatedVersion != "" {
			fmt.Fprintf(tw, "Negotiated Protocol\t%s (ALPN: %s)\n", info.TLS.NegotiatedVersion, info.TLS.ALPNProtocol)
		}
		if len(info.TLS.SupportedVersions) > 0 {
			fmt.Fprintf(tw, "Supported Protocols\t%s\n", strings.Join(info.TLS.SupportedVersions, ", "))
		}
		if info.TLS.CipherSuite != "" {
			fmt.Fprintf(tw, "Cipher Suite\t%s\n", info.TLS.CipherSuite)
		}
		if info.TLS.KeyAlgorithm != "" {
			fmt.Fprintf(tw, "Key & Signature\t%s (%s)\n", info.TLS.KeyAlgorithm, info.TLS.SignatureAlgorithm)
		}
		fmt.Fprintf(tw, "TLS Provider\t%s\n", info.TLS.TLSIssuer)
		fmt.Fprintf(tw, "TLS Expiry\t%s (%d days remaining)\n", info.TLS.TLSExpiry, info.TLS.DaysRemaining)
		fmt.Fprintf(tw, "Chain Trusted\t%v (OCSP Stapled: %v, CT SCT: %v)\n", info.TLS.ChainValid, info.TLS.OCSPStapled, info.TLS.HasCertTransparency)
		for _, w := range info.TLS.GradeWarnings {
			fmt.Fprintf(tw, "TLS Warning\t%s\n", w)
		}
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

	if info.HTTPTrace != nil && len(info.HTTPTrace.Hops) > 0 {
		var chainParts []string
		for _, h := range info.HTTPTrace.Hops {
			chainParts = append(chainParts, fmt.Sprintf("%s [%d]", h.URL, h.StatusCode))
		}
		fmt.Fprintf(tw, "HTTP Redirect Chain\t%s\n", strings.Join(chainParts, " -> "))
		wf := info.HTTPTrace.Waterfall
		if wf.StatusCode > 0 {
			fmt.Fprintf(tw, "HTTP Timing Waterfall\tDNS: %.2fms | TCP: %.2fms | TLS: %.2fms | TTFB: %.2fms | Total: %.2fms\n",
				wf.DNSMs, wf.TCPConnectMs, wf.TLSHandshakeMs, wf.TTFBMs, wf.TotalMs)
		}
	}

	if info.Metadata != nil {
		if info.Metadata.PageTitle != "" {
			fmt.Fprintf(tw, "Page Title\t%s\n", info.Metadata.PageTitle)
		}
		if info.Metadata.MetaDescription != "" {
			fmt.Fprintf(tw, "Meta Description\t%s\n", info.Metadata.MetaDescription)
		}
		if info.Metadata.RobotsTxt.Found {
			fmt.Fprintf(tw, "robots.txt\tFound (%d Disallow, %d Sitemaps)\n", len(info.Metadata.RobotsTxt.DisallowedPaths), len(info.Metadata.RobotsTxt.Sitemaps))
		} else {
			fmt.Fprintf(tw, "robots.txt\tNot found\n")
		}
		if info.Metadata.SecurityTxt.Found {
			fmt.Fprintf(tw, "security.txt\tPresent (%s)\n", strings.Join(info.Metadata.SecurityTxt.Contacts, ", "))
		} else {
			fmt.Fprintf(tw, "security.txt\tNot found\n")
		}
		if info.Metadata.Sitemap.Found {
			fmt.Fprintf(tw, "sitemap.xml\tFound (%d URLs)\n", info.Metadata.Sitemap.URLCount)
		} else {
			fmt.Fprintf(tw, "sitemap.xml\tNot found\n")
		}
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

	// --- NETWORK / PING SECTION ---
	if info.Ping != nil {
		fmt.Fprintln(tw, "\n==================================================")
		fmt.Fprintf(tw, "CATEGORY: NETWORK (PING)\n")
		fmt.Fprintln(tw, "==================================================")
		fmt.Fprintf(tw, "Reachable\t%v (%s)\n", info.Ping.Reachable, info.Ping.Method)
		fmt.Fprintf(tw, "Packet Loss\t%.0f%% (%d/%d received)\n", info.Ping.LossPercent, info.Ping.PacketsRecv, info.Ping.PacketsSent)
		if info.Ping.Reachable {
			fmt.Fprintf(tw, "Latency (Min/Avg/Max)\t%s / %s / %s\n", info.Ping.MinRTT, info.Ping.AvgRTT, info.Ping.MaxRTT)
		}
	}

	// --- SUBDOMAINS SECTION ---
	if info.Subdomains != nil {
		fmt.Fprintln(tw, "\n==================================================")
		fmt.Fprintf(tw, "CATEGORY: SUBDOMAINS (%d found, %d active)\n", info.Subdomains.TotalFound, info.Subdomains.ActiveCount)
		fmt.Fprintln(tw, "==================================================")
		for _, sub := range info.Subdomains.Subdomains {
			status := "Historical (CT)"
			if sub.Active {
				status = "Active"
			}
			details := status
			if len(sub.IPAddresses) > 0 {
				details += " | IP: " + strings.Join(sub.IPAddresses, ", ")
			}
			if sub.CNAME != "" {
				details += " | CNAME: " + sub.CNAME
			}
			if len(sub.Sources) > 0 {
				details += " [" + strings.Join(sub.Sources, "+") + "]"
			}
			fmt.Fprintf(tw, "%s\t%s\n", sub.Subdomain, details)
		}
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
