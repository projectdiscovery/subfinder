package runner

import (
	"bufio"
	"os"
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
		text := scanner.Text()
		if text == "" {
			continue
		}
		items = append(items, text)
	}
	return items, scanner.Err()
}
