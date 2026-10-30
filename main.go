package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"domain-analyzer/analyzer"
	"domain-analyzer/output"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Format     string `short:"f" long:"format" description:"Output format (tabular, json, csv)" default:"tabular"`
	CheckVulns bool   `short:"v" long:"check-vulnerabilities" description:"Check for CVE vulnerabilities (may be slow)"`
	Subdomains bool   `short:"s" long:"subdomains" description:"Enumerate subdomains via Certificate Transparency (crt.sh) & DNS"`
	Output     string `short:"o" long:"output" description:"Output results to a file"`
	Args       struct {
		Domain string `positional-arg-name:"domain" description:"Domain name to analyze"`
	} `positional-args:"yes"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	var domains []string
	if opts.Args.Domain != "" {
		domains = append(domains, opts.Args.Domain)
	}

	// Check if stdin has data
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if domain != "" {
				domains = append(domains, domain)
			}
		}
	}

	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No domains provided. Please provide a domain as an argument or pipe via stdin.")
		os.Exit(1)
	}

	var out io.Writer = os.Stdout
	if opts.Output != "" {
		f, err := os.Create(opts.Output)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	var formatter output.Formatter
	switch opts.Format {
	case "json":
		formatter = &output.JSONFormatter{}
	case "tabular":
		formatter = &output.TabularFormatter{}
	case "csv":
		formatter = &output.CSVFormatter{}
	default:
		fmt.Printf("Unknown format: %s. Defaulting to tabular.\n", opts.Format)
		formatter = &output.TabularFormatter{}
	}

	for i, domain := range domains {
		fmt.Fprintf(os.Stderr, "[%d/%d] Analyzing domain: %s...\n", i+1, len(domains), domain)

		info := analyzer.Analyze(domain, opts.CheckVulns)
		if opts.Subdomains {
			info.Subdomains = analyzer.EnumerateSubdomains(domain)
		}

		if err := formatter.Format(out, info); err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting output for %s: %v\n", domain, err)
		}

		if opts.Format == "tabular" && i < len(domains)-1 {
			fmt.Fprintln(out)
		}
	}
}
