package output

import "domain-analyzer/analyzer"

type Formatter interface {
	Format(info *analyzer.DomainInfo) error
}
