package output

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"domain-analyzer/analyzer"
)

type CSVFormatter struct {
	headerWritten bool
}

func (f *CSVFormatter) Format(w io.Writer, info *analyzer.DomainInfo) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if !f.headerWritten {
		header := []string{
			"Domain",
			"Apex Domain",
			"Registrar",
			"Expiry Date",
			"IP Address",
			"IP Owner",
			"Nameservers",
			"Mail Providers",
			"Tech Stack",
			"Has TLS",
			"TLS Issuer",
			"TLS Expiry",
			"SPF Status",
			"DMARC Status",
			"Vulnerability Count",
		}
		if err := writer.Write(header); err != nil {
			return err
		}
		f.headerWritten = true
	}

	vulnIDs := make([]string, 0, len(info.Vulnerabilities))
	for _, v := range info.Vulnerabilities {
		vulnIDs = append(vulnIDs, v.ID)
	}

	spfStatus := "N/A"
	if info.Email.SPFRecord != nil {
		spfStatus = info.Email.SPFRecord.Status
	}

	dmarcStatus := "N/A"
	if info.Email.DMARCRecord != nil {
		dmarcStatus = info.Email.DMARCRecord.Status
	}

	record := []string{
		info.Domain,
		info.ApexDomain,
		info.Registrar,
		info.ExpiryDate,
		info.DNS.IPAddress,
		info.DNS.IPOwner,
		strings.Join(info.DNS.Nameservers, "; "),
		strings.Join(info.Email.MailProviders, "; "),
		strings.Join(info.Web.TechStack, "; "),
		strconv.FormatBool(info.TLS.HasTLS),
		info.TLS.TLSIssuer,
		info.TLS.TLSExpiry,
		spfStatus,
		dmarcStatus,
		strconv.Itoa(len(info.Vulnerabilities)),
	}

	return writer.Write(record)
}
