package analyzer

import (
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

func getWhoisInfo(domain string, info *DomainInfo) error {
	result, err := whois.Whois(domain)
	if err != nil {
		return err
	}

	parsed, err := whoisparser.Parse(result)
	if err != nil {
		return err
	}

	info.Lock()
	defer info.Unlock()

	if parsed.Registrar != nil {
		info.Registrar = parsed.Registrar.Name
	}
	if parsed.Domain != nil && parsed.Domain.ExpirationDate != "" {
		info.ExpiryDate = parsed.Domain.ExpirationDate
	}

	return nil
}
