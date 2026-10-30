# Project Overview: Domain Analyzer

`domain-analyzer` is a Go-based command-line utility designed for rapid domain reconnaissance. It aggregates information from multiple sources to provide a comprehensive view of a domain's status, infrastructure, and technology stack.

## Main Technologies
- **Language:** Go (v1.27+)
- **CLI Parsing:** `github.com/jessevdk/go-flags`
- **Native Desktop UI:** `github.com/egoist/mygo` & `github.com/egoist/mygo/ui` (Pure Go, GPU-accelerated native widgets, `CGO_ENABLED=0`)
- **Persistent Storage:** `modernc.org/sqlite` (Pure Go embedded SQLite database for scan history and pivot lineage)
- **WHOIS Fetching:** `github.com/likexian/whois`
- **WHOIS Parsing:** `github.com/likexian/whois-parser`
- **Tech Stack Discovery:** `github.com/projectdiscovery/wappalyzergo`
- **Standard Library:** `net/http` (web requests), `crypto/tls` (certificate inspection), `net` (DNS lookups), `text/tabwriter` (formatting).

## Architecture
The project is structured into modular packages to ensure scalability and testability.

### Packages
- **`cmd/cli` (and root `main.go`)**: Handles CLI argument parsing using `go-flags`. It supports reading domains from positional arguments and stdin, orchestration of analysis across multiple domains, and redirection of output to files.
- **`cmd/gui`**: Native desktop application built with MyGo (`github.com/egoist/mygo/ui`). Provides a split-pane interface with persistent scan history, search filtering, detailed reconnaissance cards, and one-click drill-down (pivoting) into discovered domains and IP addresses.
- **`analyzer`**: Contains the core logic for domain and IP analysis.
  - `Analyze(domain string, checkVulns bool)`: Orchestrates domain sub-modules concurrently using `sync.WaitGroup`.
  - `AnalyzeIP(ip string, checkVulns bool)`: Orchestrates IP reconnaissance (Reverse DNS PTR, IP WHOIS/ASN/CIDR, direct `:443` TLS SAN inspection, direct HTTP/WAF/tech fingerprinting).
  - `metadata.go`: Website HTML metadata, `/robots.txt`, `/.well-known/security.txt` (RFC 9116), and `/sitemap.xml` inspector (`InspectWebsiteMetadata`).
  - `subdomains.go`: Passive subdomain enumeration via Certificate Transparency logs (`crt.sh`, `CertSpotter`) and wildcard-aware DNS resolution verification (`EnumerateSubdomains`).
  - `netdiag.go`: Ping latency & packet loss check (`RunPing`, ICMP with TCP handshake fallback) and multi-hop network path traceroute (`RunTraceroute`, supporting `traceroute`, `tracepath`, `mtr`, and `tracert` with reverse DNS hop resolution).
  - `ports.go`: Concurrent TCP host port and service banner scanner (`ScanPorts(ip string)`).
  - `favicon.go`: Website and Wappalyzer technology favicon fetching and ICO-to-PNG conversion.
  - `pivots.go`: Extracts and normalizes actionable domain and IP pivot targets from completed scans.
  - `whois.go`: Registrar and expiration date retrieval.
  - `dns.go`: IP resolution, IP ownership (WHOIS), and mail provider detection.
  - `web.go`: WWW support check and tech stack fingerprinting with version detection.
  - `waf.go`: WAF detection, implementation details (CNAME chain, edge proxy/CDN, bot management), and active enforcement probing.
  - `tls.go`: TLS certificate inspection.
  - `vulnerabilities.go`: CVE lookup via NVD API based on detected tech versions.
- **`storage`**: Persistent SQLite database (`sqlite.go`) storing serialized `DomainInfo` and `IPInfo` records, parent-child drill-down lineage (`parent_scan_id`, `pivot_reason`), and target lookup maps.
- **`output`**: Provides different formatters for displaying results. All formatters implement a shared `Formatter` interface that writes to an `io.Writer`.
  - `tabular.go`: Formatted table output using `tabwriter`.
  - `json.go`: Standard JSON serialization.
  - `csv.go`: Comma-separated values for spreadsheet compatibility.

## Future Roadmap
- **Passive Subdomain Discovery**: Integration with `crt.sh` to find subdomains via Certificate Transparency logs.
- **Metadata Analysis**: Automatic fetching and parsing of `robots.txt`, `security.txt`, and `sitemap.xml`.
- **Infrastructure Context**: Enhanced Geo-IP data and CDN/WAF detection (Cloudflare, Akamai, etc.).
- **Reconnaissance Tools**: Basic port scanning for common services (SSH, RDP, FTP) and favicon hashing for tech discovery.
- **Reputation Checks**: Integration with threat intelligence feeds (Google Safe Browsing, PhishTank).

## Building and Running

### Prerequisites
- Go 1.25 or higher.

### Build and Run
```bash
go build -o domain-analyzer
# Single domain
./domain-analyzer <domain> [--format tabular|json|csv] [--output file] [--check-vulnerabilities]
# Bulk analysis
cat domains.txt | ./domain-analyzer --format csv --output scan_results.csv
```

## Development Conventions
- **Concurrency:** All analysis modules must run in parallel. Shared state in `DomainInfo` is protected by a `sync.Mutex`.
- **Error Handling:** Non-critical errors (e.g., a timeout on one specific check) are printed as warnings to `stderr`, allowing the rest of the analysis to complete.
- **Timeouts:** HTTP and TLS connections have aggressive timeouts (10-15s) to ensure the utility remains responsive.
- **Formatting:** Adheres to standard `go fmt` conventions.
- **Output:** Progress and error messages should be directed to `stderr` to avoid polluting data output on `stdout` or files.
