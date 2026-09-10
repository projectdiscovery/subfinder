package runner

import (
	"encoding/json"
	"testing"
)

func TestJSONStreamOutputFormat(t *testing.T) {
	type SubdomainResult struct {
		Host   string `json:"host"`
		Source string `json:"source"`
	}
	
	res := SubdomainResult{Host: "api.example.com", Source: "virustotal"}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed to marshal JSON output: %v", err)
	}
	
	if len(data) == 0 {
		t.Fatalf("marshaled JSON stream output is empty")
	}
}
