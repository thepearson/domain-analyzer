package analyzer

import (
	"crypto/tls"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type RobotsTxtInfo struct {
	Found           bool     `json:"found"`
	URL             string   `json:"url,omitempty"`
	UserAgents      []string `json:"user_agents,omitempty"`
	DisallowedPaths []string `json:"disallowed_paths,omitempty"`
	AllowedPaths    []string `json:"allowed_paths,omitempty"`
	Sitemaps        []string `json:"sitemaps,omitempty"`
}

type SecurityTxtInfo struct {
	Found           bool     `json:"found"`
	URL             string   `json:"url,omitempty"`
	Contacts        []string `json:"contacts,omitempty"`
	Expires         string   `json:"expires,omitempty"`
	Encryption      []string `json:"encryption,omitempty"`
	Acknowledgments []string `json:"acknowledgments,omitempty"`
	Policy          []string `json:"policy,omitempty"`
	Hiring          []string `json:"hiring,omitempty"`
	Canonical       []string `json:"canonical,omitempty"`
}

type SitemapInfo struct {
	Found           bool     `json:"found"`
	URL             string   `json:"url,omitempty"`
	IsIndex         bool     `json:"is_index,omitempty"`
	URLCount        int      `json:"url_count"`
	SampleURLs      []string `json:"sample_urls,omitempty"`
	DiscoveredHosts []string `json:"discovered_hosts,omitempty"`
}

type WebsiteMetadata struct {
	PageTitle       string          `json:"page_title,omitempty"`
	MetaDescription string          `json:"meta_description,omitempty"`
	MetaGenerator   string          `json:"meta_generator,omitempty"`
	CanonicalURL    string          `json:"canonical_url,omitempty"`
	RobotsTxt       RobotsTxtInfo   `json:"robots_txt"`
	SecurityTxt     SecurityTxtInfo `json:"security_txt"`
	Sitemap         SitemapInfo     `json:"sitemap"`
}

func newMetadataHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 6 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// InspectWebsiteMetadata concurrently fetches and parses HTML metadata, /robots.txt,
// /.well-known/security.txt (and /security.txt), and /sitemap.xml for a domain or IP.
func InspectWebsiteMetadata(target string) *WebsiteMetadata {
	clean := NormalizeTarget(target)
	if clean == "" {
		return &WebsiteMetadata{}
	}

	client := newMetadataHTTPClient()
	meta := &WebsiteMetadata{}

	baseURL := resolveBaseWebURL(clean, client)
	if baseURL == "" {
		return meta
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	wg.Add(3)

	// 1. Fetch & parse /robots.txt
	go func() {
		defer wg.Done()
		robotsURL := strings.TrimRight(baseURL, "/") + "/robots.txt"
		body, finalURL, status := fetchMetadataResource(client, robotsURL)
		if status == http.StatusOK && len(body) > 0 && !looksLikeHTMLPage(body) {
			parsed := ParseRobotsTxt(string(body))
			parsed.Found = true
			parsed.URL = finalURL
			mu.Lock()
			meta.RobotsTxt = parsed
			mu.Unlock()
		}
	}()

	// 2. Fetch & parse /.well-known/security.txt (with fallback to /security.txt)
	go func() {
		defer wg.Done()
		candidates := []string{
			strings.TrimRight(baseURL, "/") + "/.well-known/security.txt",
			strings.TrimRight(baseURL, "/") + "/security.txt",
		}
		for _, candidateURL := range candidates {
			body, finalURL, status := fetchMetadataResource(client, candidateURL)
			if status == http.StatusOK && len(body) > 0 && !looksLikeHTMLPage(body) {
				parsed := ParseSecurityTxt(string(body))
				if parsed.Found {
					parsed.URL = finalURL
					mu.Lock()
					meta.SecurityTxt = parsed
					mu.Unlock()
					break
				}
			}
		}
	}()

	// 3. Fetch & parse root HTML page metadata (<title>, description, generator, canonical)
	go func() {
		defer wg.Done()
		body, _, status := fetchMetadataResource(client, baseURL)
		if status >= 200 && status < 400 && len(body) > 0 {
			title, desc, gen, canon := ParseHTMLPageMeta(string(body))
			mu.Lock()
			meta.PageTitle = title
			meta.MetaDescription = desc
			meta.MetaGenerator = gen
			meta.CanonicalURL = canon
			mu.Unlock()
		}
	}()

	wg.Wait()

	// 4. Fetch & parse sitemap.xml (preferring Sitemap URL from robots.txt if present)
	var sitemapCandidates []string
	for _, sm := range meta.RobotsTxt.Sitemaps {
		if strings.HasPrefix(strings.ToLower(sm), "http://") || strings.HasPrefix(strings.ToLower(sm), "https://") {
			sitemapCandidates = append(sitemapCandidates, sm)
		}
	}
	defaultSitemap := strings.TrimRight(baseURL, "/") + "/sitemap.xml"
	sitemapCandidates = append(sitemapCandidates, defaultSitemap)

	seenSM := make(map[string]bool)
	for _, smURL := range sitemapCandidates {
		if seenSM[smURL] {
			continue
		}
		seenSM[smURL] = true
		body, finalURL, status := fetchMetadataResource(client, smURL)
		if status == http.StatusOK && len(body) > 0 {
			parsed := ParseSitemapXML(body)
			if parsed.Found {
				parsed.URL = finalURL
				meta.Sitemap = parsed
				break
			}
		}
	}

	return meta
}

func resolveBaseWebURL(host string, client *http.Client) string {
	for _, scheme := range []string{"https://", "http://"} {
		u := scheme + host
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", wafUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.Request != nil && resp.Request.URL != nil {
			return resp.Request.URL.Scheme + "://" + resp.Request.URL.Host
		}
		return u
	}
	return ""
}

func fetchMetadataResource(client *http.Client, targetURL string) ([]byte, string, int) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, targetURL, 0
	}
	req.Header.Set("User-Agent", wafUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, targetURL, 0
	}
	defer resp.Body.Close()

	finalURL := targetURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, finalURL, resp.StatusCode
	}
	return data, finalURL, resp.StatusCode
}

func looksLikeHTMLPage(body []byte) bool {
	sample := strings.ToLower(strings.TrimSpace(string(body)))
	if len(sample) > 512 {
		sample = sample[:512]
	}
	return strings.HasPrefix(sample, "<!doctype html") ||
		strings.HasPrefix(sample, "<html") ||
		strings.Contains(sample, "<head>") ||
		strings.Contains(sample, "<body")
}

// ParseRobotsTxt parses a standard robots.txt file into user-agents, disallow/allow rules, and sitemaps.
func ParseRobotsTxt(raw string) RobotsTxtInfo {
	var (
		info       RobotsTxtInfo
		seenUA     = make(map[string]bool)
		seenDis    = make(map[string]bool)
		seenAllow  = make(map[string]bool)
		seenSm     = make(map[string]bool)
		maxEntries = 40
	)

	for _, line := range strings.Split(raw, "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}

		switch key {
		case "user-agent":
			if !seenUA[val] && len(info.UserAgents) < maxEntries {
				seenUA[val] = true
				info.UserAgents = append(info.UserAgents, val)
			}
		case "disallow":
			if !seenDis[val] && len(info.DisallowedPaths) < maxEntries {
				seenDis[val] = true
				info.DisallowedPaths = append(info.DisallowedPaths, val)
			}
		case "allow":
			if !seenAllow[val] && len(info.AllowedPaths) < maxEntries {
				seenAllow[val] = true
				info.AllowedPaths = append(info.AllowedPaths, val)
			}
		case "sitemap":
			if !seenSm[val] && len(info.Sitemaps) < 20 {
				seenSm[val] = true
				info.Sitemaps = append(info.Sitemaps, val)
			}
		}
	}
	return info
}

// ParseSecurityTxt parses an RFC 9116 security.txt file and validates that at least one standard directive exists.
func ParseSecurityTxt(raw string) SecurityTxtInfo {
	var info SecurityTxtInfo
	addUnique := func(slice *[]string, val string) {
		for _, existing := range *slice {
			if existing == val {
				return
			}
		}
		*slice = append(*slice, val)
	}

	for _, line := range strings.Split(raw, "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}

		switch key {
		case "contact":
			addUnique(&info.Contacts, val)
		case "expires":
			if info.Expires == "" {
				info.Expires = val
			}
		case "encryption":
			addUnique(&info.Encryption, val)
		case "acknowledgments", "acknowledgements":
			addUnique(&info.Acknowledgments, val)
		case "policy":
			addUnique(&info.Policy, val)
		case "hiring":
			addUnique(&info.Hiring, val)
		case "canonical":
			addUnique(&info.Canonical, val)
		}
	}

	if len(info.Contacts) > 0 || len(info.Policy) > 0 || info.Expires != "" || len(info.Encryption) > 0 || len(info.Acknowledgments) > 0 {
		info.Found = true
	}
	return info
}

// ParseSitemapXML parses a <urlset> or <sitemapindex> XML document and extracts URL counts, samples, and hostnames.
func ParseSitemapXML(raw []byte) SitemapInfo {
	var info SitemapInfo
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	decoder.Strict = false

	seenHosts := make(map[string]bool)
	inLoc := false
	rootFound := false

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch se := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(se.Name.Local)
			if !rootFound {
				if name == "sitemapindex" {
					info.IsIndex = true
					rootFound = true
				} else if name == "urlset" {
					info.IsIndex = false
					rootFound = true
				}
			}
			if name == "loc" {
				inLoc = true
			}
		case xml.EndElement:
			if strings.ToLower(se.Name.Local) == "loc" {
				inLoc = false
			}
		case xml.CharData:
			if inLoc {
				loc := strings.TrimSpace(string(se))
				if loc != "" {
					info.URLCount++
					if len(info.SampleURLs) < 15 {
						info.SampleURLs = append(info.SampleURLs, loc)
					}
					if u, err := url.Parse(loc); err == nil && u.Hostname() != "" {
						h := strings.ToLower(u.Hostname())
						if !seenHosts[h] {
							seenHosts[h] = true
							info.DiscoveredHosts = append(info.DiscoveredHosts, h)
						}
					}
				}
			}
		}
	}

	sort.Strings(info.DiscoveredHosts)
	if rootFound || info.URLCount > 0 {
		info.Found = true
	}
	return info
}

var (
	reHTMLTitle     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reMetaDesc1     = regexp.MustCompile(`(?is)<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']`)
	reMetaDesc2     = regexp.MustCompile(`(?is)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']`)
	reMetaGen1      = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	reMetaGen2      = regexp.MustCompile(`(?is)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']`)
	reLinkCanonical = regexp.MustCompile(`(?is)<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']`)
	reWhitespace    = regexp.MustCompile(`\s+`)
)

// ParseHTMLPageMeta extracts the page <title>, meta description, meta generator, and canonical URL from HTML.
func ParseHTMLPageMeta(htmlBody string) (title, description, generator, canonical string) {
	cleanText := func(s string) string {
		s = strings.TrimSpace(reWhitespace.ReplaceAllString(s, " "))
		s = strings.ReplaceAll(s, "&amp;", "&")
		s = strings.ReplaceAll(s, "&#39;", "'")
		s = strings.ReplaceAll(s, "&quot;", `"`)
		return s
	}

	if m := reHTMLTitle.FindStringSubmatch(htmlBody); len(m) > 1 {
		title = cleanText(m[1])
	}
	if m := reMetaDesc1.FindStringSubmatch(htmlBody); len(m) > 1 {
		description = cleanText(m[1])
	} else if m := reMetaDesc2.FindStringSubmatch(htmlBody); len(m) > 1 {
		description = cleanText(m[1])
	}
	if m := reMetaGen1.FindStringSubmatch(htmlBody); len(m) > 1 {
		generator = cleanText(m[1])
	} else if m := reMetaGen2.FindStringSubmatch(htmlBody); len(m) > 1 {
		generator = cleanText(m[1])
	}
	if m := reLinkCanonical.FindStringSubmatch(htmlBody); len(m) > 1 {
		canonical = strings.TrimSpace(m[1])
	}
	return title, description, generator, canonical
}
