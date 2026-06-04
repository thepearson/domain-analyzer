# Snoopy (Domain Analyzer)

`snoopy` is a rapid domain reconnaissance tool written in Go. it aggregates information from multiple sources to provide a comprehensive view of a domain's status, infrastructure, and technology stack.

## Features

- **WHOIS Information**: Retrieves registrar and domain expiration details.
- **DNS & IP Analysis**: Resolves IP addresses and identifies the IP owner (ISP/Hosting Provider).
- **Mail Provider Detection**: Identifies email services (e.g., Google Workspace, Microsoft 365, Proton Mail) by analyzing DNS MX records.
- **Web Discovery**: Checks for `www.` support and fingerprints the technology stack using Wappalyzer.
- **TLS/SSL Inspection**: Extracts certificate issuer and expiry information.

## Installation

### Prerequisites

- [Go](https://golang.org/dl/) 1.25 or higher.

### From Source

```bash
git clone https://github.com/yourusername/domain-analyzer.git
cd domain-analyzer
go build -o snoopy
```

## Usage

You can run `snoopy` by providing a domain name as a positional argument or using the `-domain` flag.

```bash
# Direct execution
go run main.go google.com

# Using the built binary
./snoopy nextjs.org

# Using the -domain flag
./snoopy -domain vercel.com
```

### Example Output

```text
Analyzing domain: google.com...

--------------------------------------------------
Domain:        google.com
Registrar:     MarkMonitor Inc.
Domain Expiry: 2028-09-14T04:00:00Z
--------------------------------------------------
Supports WWW:  true
Has TLS:       true
TLS Provider:  Google Trust Services
TLS Expiry:    2026-08-10T18:35:20Z
--------------------------------------------------
IP Address:    142.250.183.46
IP Owner:      Google LLC (GOGL)
Mail Providers: Google Workspace
--------------------------------------------------
Tech Stack:    HTTP/3, Google Web Server
--------------------------------------------------
```

## Development

### Running Tests

To run the unit tests for the mail provider identification logic:

```bash
go test -v .
```

### Project Structure

- `main.go`: Core logic and orchestration of analysis modules.
- `main_test.go`: Unit tests for critical logic.
- `GEMINI.md`: Project-specific instructions and architecture overview.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
