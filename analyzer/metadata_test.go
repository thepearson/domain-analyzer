package analyzer

import (
	"testing"
)

func TestParseRobotsTxt(t *testing.T) {
	raw := `# Example robots.txt
User-agent: *
Disallow: /admin/
Disallow: /internal/api
Allow: /public/
Sitemap: https://portal.example.co.nz/sitemap.xml
`
	res := ParseRobotsTxt(raw)
	if len(res.UserAgents) != 1 || res.UserAgents[0] != "*" {
		t.Errorf("unexpected UserAgents: %v", res.UserAgents)
	}
	if len(res.DisallowedPaths) != 2 || res.DisallowedPaths[0] != "/admin/" || res.DisallowedPaths[1] != "/internal/api" {
		t.Errorf("unexpected DisallowedPaths: %v", res.DisallowedPaths)
	}
	if len(res.AllowedPaths) != 1 || res.AllowedPaths[0] != "/public/" {
		t.Errorf("unexpected AllowedPaths: %v", res.AllowedPaths)
	}
	if len(res.Sitemaps) != 1 || res.Sitemaps[0] != "https://portal.example.co.nz/sitemap.xml" {
		t.Errorf("unexpected Sitemaps: %v", res.Sitemaps)
	}
}

func TestParseSecurityTxt(t *testing.T) {
	raw := `Contact: mailto:security@example.co.nz
Contact: https://example.co.nz/security-report
Expires: 2027-01-01T00:00:00.000Z
Policy: https://example.co.nz/security-policy
Encryption: https://example.co.nz/pgp-key.txt
Acknowledgments: https://example.co.nz/hall-of-fame
`
	res := ParseSecurityTxt(raw)
	if !res.Found {
		t.Fatalf("expected security.txt to be marked Found")
	}
	if len(res.Contacts) != 2 || res.Contacts[0] != "mailto:security@example.co.nz" {
		t.Errorf("unexpected Contacts: %v", res.Contacts)
	}
	if res.Expires != "2027-01-01T00:00:00.000Z" {
		t.Errorf("unexpected Expires: %s", res.Expires)
	}
	if len(res.Policy) != 1 || res.Policy[0] != "https://example.co.nz/security-policy" {
		t.Errorf("unexpected Policy: %v", res.Policy)
	}
}

func TestParseSitemapXML(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://portal.example.co.nz/</loc></url>
  <url><loc>https://portal.example.co.nz/login</loc></url>
  <url><loc>https://docs.example.co.nz/guide</loc></url>
</urlset>`)

	res := ParseSitemapXML(raw)
	if !res.Found || res.IsIndex {
		t.Fatalf("expected URL set sitemap Found=true IsIndex=false, got %+v", res)
	}
	if res.URLCount != 3 {
		t.Errorf("expected URLCount=3, got %d", res.URLCount)
	}
	if len(res.DiscoveredHosts) != 2 || res.DiscoveredHosts[0] != "docs.example.co.nz" || res.DiscoveredHosts[1] != "portal.example.co.nz" {
		t.Errorf("unexpected DiscoveredHosts: %v", res.DiscoveredHosts)
	}
}

func TestParseHTMLPageMeta(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head>
  <title>Example Portal &amp; Dashboard</title>
  <meta name="description" content="Official portal for Example NZ.">
  <meta name="generator" content="Hugo 0.125.0">
  <link rel="canonical" href="https://portal.example.co.nz/">
</head>
<body></body>
</html>`

	title, desc, gen, canon := ParseHTMLPageMeta(html)
	if title != "Example Portal & Dashboard" {
		t.Errorf("unexpected title: %q", title)
	}
	if desc != "Official portal for Example NZ." {
		t.Errorf("unexpected description: %q", desc)
	}
	if gen != "Hugo 0.125.0" {
		t.Errorf("unexpected generator: %q", gen)
	}
	if canon != "https://portal.example.co.nz/" {
		t.Errorf("unexpected canonical: %q", canon)
	}
}

