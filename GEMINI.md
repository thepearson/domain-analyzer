# Project Overview: Domain Analyzer

`domain-analyzer` is a Go-based command-line utility designed for rapid domain reconnaissance. It aggregates information from multiple sources to provide a comprehensive view of a domain's status, infrastructure, and technology stack.

## Main Technologies
- **Language:** Go (v1.25.0)
- **CLI Parsing:** `github.com/jessevdk/go-flags`
- **WHOIS Fetching:** `github.com/likexian/whois`
- **WHOIS Parsing:** `github.com/likexian/whois-parser`
- **Tech Stack Discovery:** `github.com/projectdiscovery/wappalyzergo`
- **Standard Library:** `net/http` (web requests), `crypto/tls` (certificate inspection), `net` (DNS lookups), `text/tabwriter` (formatting).

## Architecture
The project is structured into modular packages to ensure scalability and testability.

### Packages
- **`main`**: Handles CLI argument parsing using `go-flags` and orchestrates the analysis and output.
- **`analyzer`**: Contains the core logic for domain analysis.
  - `Analyze(domain string, checkVulns bool)`: Orchestrates sub-modules concurrently using `sync.WaitGroup`.
  - `whois.go`: Registrar and expiration date retrieval.
  - `dns.go`: IP resolution, IP ownership (WHOIS), and mail provider detection.
  - `web.go`: WWW support check and tech stack fingerprinting with version detection.
  - `tls.go`: TLS certificate inspection.
  - `vulnerabilities.go`: CVE lookup via NVD API based on detected tech versions.
- **`output`**: Provides different formatters for displaying results.
  - `tabular.go`: Formatted table output using `tabwriter`.
  - `json.go`: Standard JSON serialization.

## Building and Running

### Prerequisites
- Go 1.25 or higher.

### Build and Run
```bash
go build -o domain-analyzer
./domain-analyzer <domain> [--format tabular|json] [--check-vulnerabilities]
```

## Development Conventions
- **Concurrency:** All analysis modules must run in parallel. Shared state in `DomainInfo` is protected by a `sync.Mutex`.
- **Error Handling:** Non-critical errors (e.g., a timeout on one specific check) are printed as warnings, allowing the rest of the analysis to complete.
- **Timeouts:** HTTP and TLS connections have aggressive timeouts (10-15s) to ensure the utility remains responsive.
- **Formatting:** Adheres to standard `go fmt` conventions.
