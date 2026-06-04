package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/projectdiscovery/wappalyzergo"
)

type DomainInfo struct {
	Domain           string
	Registrar        string
	ExpiryDate       string
	SupportsWWW      bool
	HasTLS           bool
	TLSIssuer        string
	TLSExpiry        string
	TechStack        []string
	IPAddress        string
	IPOwner          string
}

func main() {
	domainPtr := flag.String("domain", "", "Domain name to analyze")
	flag.Parse()

	domain := *domainPtr
	if domain == "" {
		if len(flag.Args()) > 0 {
			domain = flag.Args()[0]
		} else {
			fmt.Println("Please provide a domain name using -domain flag or as a positional argument.")
			os.Exit(1)
		}
	}

	info := &DomainInfo{Domain: domain}

	fmt.Printf("Analyzing domain: %s...\n\n", domain)

	// 1. WHOIS info
	err := getWhoisInfo(domain, info)
	if err != nil {
		fmt.Printf("Warning: Error fetching WHOIS info: %v\n", err)
	}

	// 2. DNS & IP Ownership
	err = getIPInfo(domain, info)
	if err != nil {
		fmt.Printf("Warning: Error fetching IP info: %v\n", err)
	}

	// 3. WWW support and Tech Stack
	err = getWebInfo(domain, info)
	if err != nil {
		fmt.Printf("Warning: Error fetching web info: %v\n", err)
	}

	// 4. TLS info
	err = getTLSInfo(domain, info)
	if err != nil {
		fmt.Printf("Warning: Error fetching TLS info: %v\n", err)
	}

	printResult(info)
}

func getWhoisInfo(domain string, info *DomainInfo) error {
	result, err := whois.Whois(domain)
	if err != nil {
		return err
	}

	parsed, err := whoisparser.Parse(result)
	if err != nil {
		return err
	}

	if parsed.Registrar != nil {
		info.Registrar = parsed.Registrar.Name
	}
	if parsed.Domain != nil && parsed.Domain.ExpirationDate != "" {
		info.ExpiryDate = parsed.Domain.ExpirationDate
	}

	return nil
}

func getIPInfo(domain string, info *DomainInfo) error {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return err
	}

	info.IPAddress = ips[0].String()

	// Find IP owner via WHOIS
	result, err := whois.Whois(info.IPAddress)
	if err == nil {
		// IP WHOIS is often less structured. Let's try to find common labels.
		lines := strings.Split(result, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			lowerLine := strings.ToLower(line)
			if strings.HasPrefix(lowerLine, "orgname:") || 
			   strings.HasPrefix(lowerLine, "organization:") ||
			   strings.HasPrefix(lowerLine, "descr:") ||
			   strings.HasPrefix(lowerLine, "owner:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					info.IPOwner = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	return nil
}

func getWebInfo(domain string, info *DomainInfo) error {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Check WWW support
	wwwDomain := "www." + domain
	resp, err := client.Get("https://" + wwwDomain)
	if err != nil {
		resp, err = client.Get("http://" + wwwDomain)
	}
	if err == nil {
		info.SupportsWWW = true
		resp.Body.Close()
	}

	// Fetch homepage for tech stack analysis
	targetURL := "https://" + domain
	resp, err = client.Get(targetURL)
	if err != nil {
		targetURL = "http://" + domain
		resp, err = client.Get(targetURL)
	}

	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		wappalyzerClient, _ := wappalyzer.New()
		fingerprints := wappalyzerClient.Fingerprint(resp.Header, body)
		
		techs := []string{}
		for tech := range fingerprints {
			techs = append(techs, tech)
		}
		info.TechStack = techs
	}

	return nil
}

func getTLSInfo(domain string, info *DomainInfo) error {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		info.HasTLS = true
		if len(certs[0].Issuer.Organization) > 0 {
			info.TLSIssuer = certs[0].Issuer.Organization[0]
		} else {
			info.TLSIssuer = certs[0].Issuer.CommonName
		}
		info.TLSExpiry = certs[0].NotAfter.Format(time.RFC3339)
	}

	return nil
}

func printResult(info *DomainInfo) {
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Domain:        %s\n", info.Domain)
	fmt.Printf("Registrar:     %s\n", info.Registrar)
	fmt.Printf("Domain Expiry: %s\n", info.ExpiryDate)
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Supports WWW:  %v\n", info.SupportsWWW)
	fmt.Printf("Has TLS:       %v\n", info.HasTLS)
	if info.HasTLS {
		fmt.Printf("TLS Provider:  %s\n", info.TLSIssuer)
		fmt.Printf("TLS Expiry:    %s\n", info.TLSExpiry)
	}
	fmt.Println("--------------------------------------------------")
	fmt.Printf("IP Address:    %s\n", info.IPAddress)
	fmt.Printf("IP Owner:      %s\n", info.IPOwner)
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Tech Stack:    %s\n", strings.Join(info.TechStack, ", "))
	fmt.Println("--------------------------------------------------")
}
