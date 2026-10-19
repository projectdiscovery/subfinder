// Package archive contains parsing helpers shared by archive sources.
package archive

import "strings"

// DecodeLine decodes up to three layers of URL escapes without letting an
// unrelated malformed escape prevent valid escapes from being decoded. Any
// percent-prefixed hostname-shaped text left afterward is ambiguous: it may be
// an invalid escape or a fourth encoding layer. Exclude that span rather than
// interpreting escape digits as part of a hostname.
func DecodeLine(line string) string {
	for range 3 {
		decoded := decodeLayer(line)
		if decoded == line {
			break
		}
		line = decoded
	}
	if !strings.Contains(line, "%") {
		return line
	}
	b := []byte(line)
	for i := 0; i < len(b); i++ {
		if b[i] != '%' {
			continue
		}
		b[i] = ' '
		for i+1 < len(b) && hostnameByte(b[i+1]) {
			i++
			b[i] = ' '
		}
	}
	return string(b)
}

func decodeLayer(line string) string {
	if !strings.ContainsAny(line, "%+") {
		return line
	}
	b := make([]byte, 0, len(line))
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '+':
			b = append(b, ' ')
		case line[i] == '%' && i+2 < len(line):
			high, low := unhex(line[i+1]), unhex(line[i+2])
			if high >= 0 && low >= 0 {
				b = append(b, byte(high<<4|low))
				i += 2
			} else {
				// A nonhex guard keeps this malformed percent from becoming a
				// valid escape when neighboring bytes decode in a later pass.
				// The final ambiguity filter removes the guard with its span.
				b = append(b, '%', '_')
			}
		case line[i] == '%':
			b = append(b, '%', '_')
		default:
			b = append(b, line[i])
		}
	}
	return string(b)
}

func unhex(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b - 'a' + 10)
	case b >= 'A' && b <= 'F':
		return int(b - 'A' + 10)
	default:
		return -1
	}
}

// Keep in step with the source extractor's ASCII hostname character class.
func hostnameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '*' || b == '_' || b == '.' || b == '-'
}
