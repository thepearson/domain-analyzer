# Domain Analyzer

`domain-analyzer` is a rapid domain reconnaissance tool written in Go. it aggregates information from multiple sources to provide a comprehensive view of a domain's status, infrastructure, and technology stack.

## Example

```
Analyzing domain: google.com...

==================================================
CATEGORY: DNS
==================================================
Domain          google.com
Registrar       MarkMonitor Inc.
Domain Expiry   2028-09-14T04:00:00Z
IP Address      142.251.42.110
IP Owner        Google LLC (GOGL)
WWW DNS Result  142.251.153.119
Nameservers     ns1.google.com., ns3.google.com., ns2.google.com., ns4.google.com.
DNS Providers   Google Cloud DNS
CAA Issuers     pki.goog
CAA Wildcards   
CAA Raw         0 issue "pki.goog"

==================================================
CATEGORY: EMAIL
==================================================
Mail Providers  Google Workspace
SPF Status      [Warning] Partial enforcement; unauthorized emails may still be delivered to spam.
SPF Policy      Soft Fail (~all)
SPF Includes    _spf.google.com
SPF Raw         v=spf1 include:_spf.google.com ~all
DMARC Status    [Secure] Maximum protection; unauthorized emails are rejected by receivers.
DMARC Policy    reject
DMARC Reports   mailto:mailauth-reports@google.com
DMARC Raw       v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com

==================================================
CATEGORY: SSL/TLS
==================================================
Has TLS       true
TLS Provider  Google Trust Services
TLS Expiry    2026-08-10T18:35:20Z
SAN Domains   *.google.com, *.appengine.google.com, *.bdn.dev, *.origin-test.bdn.dev, *.cloud.google.com, *.crowdsource.google.com, *.datacompute.google.com, *.google.ca, *.google.cl, *.google.co.in, *.google.co.jp, *.google.co.uk, *.google.com.ar, *.google.com.au, *.google.com.br, *.google.com.co, *.google.com.mx, *.google.com.tr, *.google.com.vn, *.google.de, *.google.es, *.google.fr, *.google.hu, *.google.it, *.google.nl, *.google.pl, *.google.pt, *.gemini.cloud.google.com, *.gstatic.com, *.metric.gstatic.com, *.gvt1.com, *.gcpcdn.gvt1.com, *.gvt2.com, *.gcp.gvt2.com, *.url.google.com, *.youtube-nocookie.com, *.ytimg.com, ai.android, android.com, *.android.com, *.flash.android.com, g.co, *.g.co, goo.gl, www.goo.gl, google-analytics.com, *.google-analytics.com, google.com, googlecommerce.com, *.googlecommerce.com, urchin.com, *.urchin.com, youtu.be, youtube.com, *.youtube.com, music.youtube.com, *.music.youtube.com, youtubeeducation.com, *.youtubeeducation.com, youtubekids.com, *.youtubekids.com, yt.be, *.yt.be, android.clients.google.com, *.aistudio.google.com

==================================================
CATEGORY: WEB
==================================================
Tech Stack                         Google Web Server, HTTP/3
Header: Content-Security-Policy    Missing
Header: Permissions-Policy         Missing
Header: Referrer-Policy            Missing
Header: Strict-Transport-Security  Missing
Header: X-Content-Type-Options     Missing
Header: X-Frame-Options            SAMEORIGIN

==================================================
CATEGORY: VULNERABILITIES
==================================================
CVE Check  No known vulnerabilities found for detected versions
==================================================
```

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
- `-v, --check-vulnerabilities`: Check for CVE vulnerabilities.
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
