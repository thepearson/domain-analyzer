package output

import (
	"domain-analyzer/analyzer"
	"io"
)

type Formatter interface {
	Format(w io.Writer, info *analyzer.DomainInfo) error
}
