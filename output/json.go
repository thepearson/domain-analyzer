package output

import (
	"encoding/json"
	"io"

	"domain-analyzer/analyzer"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Format(w io.Writer, info *analyzer.DomainInfo) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info)
}
