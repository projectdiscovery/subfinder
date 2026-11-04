package subscraping

import (
	"math/rand"
	"strings"

	"github.com/projectdiscovery/gologger"
)

const MultipleKeyPartsLength = 2

// PickRandom returns a random usable (non-zero-value) entry from v, e.g. a
// non-empty API key. A pool mixing blank and valid entries - such as a
// provider-config list with some key slots left empty - must not make the
// source skip or authenticate nondeterministically depending on the draw,
// so blank entries are excluded before picking.
func PickRandom[T comparable](v []T, sourceName string) T {
	var zero T
	usable := make([]T, 0, len(v))
	for _, item := range v {
		if item != zero {
			usable = append(usable, item)
		}
	}
	if len(usable) == 0 {
		gologger.Debug().Msgf("Cannot use the %s source because there was no API key/secret defined for it.", sourceName)
		return zero
	}
	return usable[rand.Intn(len(usable))]
}

func CreateApiKeys[T any](keys []string, provider func(k, v string) T) []T {
	var result []T
	for _, key := range keys {
		if keyPartA, keyPartB, ok := createMultiPartKey(key); ok {
			result = append(result, provider(keyPartA, keyPartB))
		}
	}
	return result
}

func createMultiPartKey(key string) (keyPartA, keyPartB string, ok bool) {
	parts := strings.Split(key, ":")
	ok = len(parts) == MultipleKeyPartsLength

	if ok {
		keyPartA = parts[0]
		keyPartB = parts[1]
	}

	return
}
