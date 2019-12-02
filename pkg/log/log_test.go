package log

import (
	"fmt"
	"strings"
	"testing"

	"github.com/logrusorgru/aurora"
)

func TestGetLabel(t *testing.T) {
	tests := []struct {
		level    Level
		label    string
		expected string
	}{
		{Fatal, "", fmt.Sprintf("[%s] ", aurora.Bold(aurora.Red(labels[Fatal])).String())},
		{Silent, "hello", ""},
		{Error, "error", fmt.Sprintf("[%s] ", aurora.Red(labels[Error]).String())},
		{Info, "", fmt.Sprintf("[%s] ", aurora.Blue(labels[Info]).String())},
		{Warning, "", fmt.Sprintf("[%s] ", aurora.Yellow(labels[Warning]).String())},
		{Verbose, "dns", fmt.Sprintf("[%s] ", aurora.Blue("dns").String())},
	}

	sb := &strings.Builder{}
	for _, test := range tests {
		sb.Reset()
		getLabel(test.level, test.label, sb)
		data := sb.String()
		if !strings.EqualFold(data, test.expected) {
			t.Fatalf("Expected %s got %s\n", test.expected, data)
		}
	}
}
