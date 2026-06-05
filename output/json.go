package output

import (
	"encoding/json"
	"os"

	"domain-analyzer/analyzer"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Format(info *analyzer.DomainInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info)
}
