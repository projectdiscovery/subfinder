package runner

import (
	"bufio"
	"os"
	"strings"

	"github.com/pkg/errors"
)

func loadFromFile(file string) ([]string, error) {
	var items []string
	f, err := os.Open(file)
	if err != nil {
		return items, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text, err := sanitize(scanner.Text())
		if errors.Is(err, ErrEmptyInput) {
			continue
		}
		items = append(items, text)
	}
	return items, scanner.Err()
}

var (
	ErrEmptyInput = errors.New("empty data")
)

func sanitize(data string) (string, error) {
	data = strings.Trim(data, "\n\t\"' ")
	if data == "" {
		return "", ErrEmptyInput
	}

	return data, nil
}
