# Project Overview: Snoopy (Domain Analyzer)

`snoopy` is a Go-based command-line utility designed for rapid domain reconnaissance. It aggregates information from multiple sources to provide a comprehensive view of a domain's status, infrastructure, and technology stack.

## Main Technologies
- **Language:** Go (v1.25.0)
- **WHOIS Fetching:** `github.com/likexian/whois`
- **WHOIS Parsing:** `github.com/likexian/whois-parser`
- **Tech Stack Discovery:** `github.com/projectdiscovery/wappalyzergo`
- **Standard Library:** `net/http` (web requests), `crypto/tls` (certificate inspection), `net` (DNS lookups), `flag` (CLI arguments).

## Architecture
The project is structured as a single-package Go application.
- `main.go`: Contains the core logic, CLI flag parsing, and the orchestration of various analysis modules.
- **Analysis Modules:**
  - `getWhoisInfo`: Retrieves registrar and domain expiration details.
  - `getIPInfo`: Resolves DNS A records and identifies the IP owner (ISP/Hosting Provider) via IP WHOIS.
  - `getWebInfo`: Checks for `www.` subdomain support and fingerprints the technology stack.
  - `getTLSInfo`: Established a TLS connection to extract certificate issuer and expiry information.

## Building and Running

### Prerequisites
- Go 1.25 or higher.

### Run directly
```bash
go run main.go <domain>
```

### Build binary
```bash
go build -o domain-analyzer
./domain-analyzer <domain>
```

### Usage Examples
```bash
./domain-analyzer google.com
./domain-analyzer nextjs.org -domain vercel.com
```

## Development Conventions
- **Error Handling:** Non-critical errors (e.g., a timeout on one specific check) are printed as warnings to `stdout` rather than causing a hard exit, allowing the rest of the analysis to complete.
- **Timeouts:** HTTP and TLS connections have aggressive timeouts (10-15s) to ensure the utility remains responsive.
- **Formatting:** Adheres to standard `go fmt` conventions.
