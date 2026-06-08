package main

import (
	"fmt"
	"os"

	"domain-analyzer/analyzer"
	"domain-analyzer/output"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Format     string `short:"f" long:"format" description:"Output format (tabular, json)" default:"tabular"`
	CheckVulns bool   `short:"v" long:"check-vulnerabilities" description:"Check for CVE vulnerabilities (may be slow)"`
	Args       struct {
		Domain string `positional-arg-name:"domain" description:"Domain name to analyze"`
	} `positional-args:"yes" required:"yes"`
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

	domain := opts.Args.Domain
	fmt.Printf("Analyzing domain: %s...\n\n", domain)

	info := analyzer.Analyze(domain, opts.CheckVulns)

	var formatter output.Formatter
	switch opts.Format {
	case "json":
		formatter = &output.JSONFormatter{}
	case "tabular":
		formatter = &output.TabularFormatter{}
	default:
		fmt.Printf("Unknown format: %s. Defaulting to tabular.\n", opts.Format)
		formatter = &output.TabularFormatter{}
	}

	if err := formatter.Format(info); err != nil {
		fmt.Printf("Error formatting output: %v\n", err)
		os.Exit(1)
	}
}
