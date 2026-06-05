# Domain Analyzer

`domain-analyzer` is a rapid domain reconnaissance tool written in Go. it aggregates information from multiple sources to provide a comprehensive view of a domain's status, infrastructure, and technology stack.

## Features

- **WHOIS Information**: Retrieves registrar and domain expiration details.
- **DNS & IP Analysis**: Resolves IP addresses and identifies the IP owner (ISP/Hosting Provider).
- **Mail Provider Detection**: Identifies email services (e.g., Google Workspace, Microsoft 365, Proton Mail) by analyzing DNS MX records.
- **Web Discovery**: Checks for `www.` support and fingerprints the technology stack using Wappalyzer.
- **TLS/SSL Inspection**: Extracts certificate issuer and expiry information.
- **Concurrent Execution**: All analysis modules run in parallel for maximum speed.
- **Flexible Output**: Supports both Tabular (formatted console) and JSON output formats.

## Installation

### Prerequisites

- [Go](https://golang.org/dl/) 1.25 or higher.

### From Source

```bash
git clone https://github.com/yourusername/domain-analyzer.git
cd domain-analyzer
go build -o domain-analyzer
```

## Usage

Provide a domain name as a positional argument.

```bash
# Basic usage (tabular output)
./domain-analyzer google.com

# JSON output
./domain-analyzer google.com --format json
```

### Options

- `-f, --format`: Output format. Options: `tabular` (default), `json`.
- `-h, --help`: Show help message.

## Development

### Project Structure

The project follows a modular structure:
- `main.go`: Entry point and CLI argument parsing using `go-flags`.
- `analyzer/`: Package containing core analysis logic (WHOIS, DNS, Web, TLS).
- `output/`: Package for formatting results into different output types.

### Running Tests

```bash
go test ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
