package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func getVulnerabilities(info *DomainInfo) error {
	client := &http.Client{Timeout: 10 * time.Second}

	vulnMap := make(map[string]Vulnerability)

	// Only check techs with versions for now to keep it targeted and avoid rate limits
	for _, tech := range info.Web.TechDetails {
		if tech.Version == "" {
			continue
		}

		query := fmt.Sprintf("%s %s", tech.Name, tech.Version)
		apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=3", url.QueryEscape(query))

		resp, err := client.Get(apiURL)
		if err != nil {
			continue
		}

		var nvd NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvd); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, v := range nvd.Vulnerabilities {
			if _, exists := vulnMap[v.CVE.ID]; exists {
				continue
			}

			desc := ""
			for _, d := range v.CVE.Descriptions {
				if d.Lang == "en" {
					desc = d.Value
					break
				}
			}

			// Truncate description for better display
			if len(desc) > 150 {
				desc = desc[:147] + "..."
			}

			severity := "Unknown"
			if len(v.CVE.Metrics.CvssMetricV31) > 0 {
				severity = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
			}

			vulnMap[v.CVE.ID] = Vulnerability{
				ID:          v.CVE.ID,
				Description: desc,
				Severity:    severity,
				URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CVE.ID),
			}
		}

		// Wait a bit to avoid aggressive rate limiting
		time.Sleep(1 * time.Second)
	}

	vulns := make([]Vulnerability, 0, len(vulnMap))
	for _, v := range vulnMap {
		vulns = append(vulns, v)
	}

	info.Lock()
	info.Vulnerabilities = vulns
	info.Unlock()

	return nil
}
