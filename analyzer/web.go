package analyzer

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/projectdiscovery/wappalyzergo"
)

func getSecurityHeaders(domain string, info *DomainInfo) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	targetURL := "https://" + domain
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = "http://" + domain
		resp, err = client.Get(targetURL)
	}

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	headersToCheck := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	results := make(map[string]string)
	for _, h := range headersToCheck {
		val := resp.Header.Get(h)
		if val != "" {
			results[h] = val
		} else {
			results[h] = "Missing"
		}
	}

	info.Lock()
	info.Web.SecurityHeaders = results
	info.Unlock()

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

	// Fetch homepage for tech stack analysis
	targetURL := "https://" + domain
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = "http://" + domain
		resp, err = client.Get(targetURL)
	}

	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		wappalyzerClient, err := wappalyzer.New()
		if err != nil {
			return err
		}
		fingerprints := wappalyzerClient.Fingerprint(resp.Header, body)

		techs := []string{}
		for tech := range fingerprints {
			techs = append(techs, tech)
		}

		info.Lock()
		info.Web.TechStack = techs
		info.Unlock()
	}

	return nil
}

