package analyzer

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// LookupTechAppInfo returns the official website URL and icon name for a technology from Wappalyzer's database.
func LookupTechAppInfo(name string) (website string, icon string) {
	cleanName := strings.TrimSpace(strings.SplitN(name, ":", 2)[0])
	if cleanName == "" {
		return "", ""
	}
	client := getWappalyzerClient()
	if client == nil {
		return "", ""
	}
	compiled := client.GetCompiledFingerprints()
	if compiled == nil || len(compiled.Apps) == 0 {
		return "", ""
	}

	if fp, ok := compiled.Apps[cleanName]; ok && fp != nil {
		info := wappalyzer.AppInfoFromFingerprint(fp)
		return strings.TrimSpace(info.Website), strings.TrimSpace(info.Icon)
	}

	for appName, fp := range compiled.Apps {
		if strings.EqualFold(appName, cleanName) && fp != nil {
			info := wappalyzer.AppInfoFromFingerprint(fp)
			return strings.TrimSpace(info.Website), strings.TrimSpace(info.Icon)
		}
	}
	return "", ""
}

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

		wappalyzerClient := getWappalyzerClient()
		if wappalyzerClient == nil {
			return fmt.Errorf("failed to initialize wappalyzer client")
		}

		// FingerprintWithInfo returns map[string]AppInfo where keys can be "Tech:Version"
		fingerprints := wappalyzerClient.FingerprintWithInfo(resp.Header, body)

		techs := []string{}
		details := []TechDetail{}
		for techWithVersion, appInfo := range fingerprints {
			name := techWithVersion
			version := ""

			if parts := strings.SplitN(techWithVersion, ":", 2); len(parts) == 2 {
				name = parts[0]
				version = parts[1]
			}

			website := strings.TrimSpace(appInfo.Website)
			icon := strings.TrimSpace(appInfo.Icon)
			if website == "" {
				website, icon = LookupTechAppInfo(name)
			}

			techs = append(techs, name)
			details = append(details, TechDetail{
				Name:    name,
				Version: version,
				Website: website,
				Icon:    icon,
			})
		}

		sort.Strings(techs)
		sort.Slice(details, func(i, j int) bool {
			return details[i].Name < details[j].Name
		})

		PopulateTechFavicons(details)

		finalPageURL := targetURL
		if resp.Request != nil && resp.Request.URL != nil {
			finalPageURL = resp.Request.URL.String()
		}
		favicon := FetchFavicon(finalPageURL, body, client)

		info.Lock()
		info.Web.TechStack = techs
		info.Web.TechDetails = details
		info.Web.Favicon = favicon
		info.Unlock()

	}

	return nil
}
