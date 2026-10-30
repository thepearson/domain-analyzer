package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
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

// LookupVulnerabilities queries the NVD CVE API for any detected technologies that have a version number.
func LookupVulnerabilities(details []TechDetail) ([]Vulnerability, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	vulnMap := make(map[string]Vulnerability)

	versionedIdx := 0
	for _, tech := range details {
		if tech.Version == "" {
			continue
		}
		if versionedIdx > 0 {
			time.Sleep(1 * time.Second)
		}
		versionedIdx++

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
	}

	vulns := make([]Vulnerability, 0, len(vulnMap))
	for _, v := range vulnMap {
		vulns = append(vulns, v)
	}
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].ID < vulns[j].ID
	})
	return vulns, nil
}

func getVulnerabilities(info *DomainInfo) error {
	vulns, err := LookupVulnerabilities(info.Web.TechDetails)
	if err != nil {
		return err
	}
	info.Lock()
	info.VulnsChecked = true
	info.Vulnerabilities = vulns
	info.Unlock()
	return nil
}
