package resolve

import (
	"bufio"
	"math/rand"
	"os"
	"time"
)

// DefaultResolvers contains the default list of resolvers known to be good
var DefaultResolvers = []string{
	"1.1.1.1",        // Cloudflare primary
	"1.0.0.1",        // Cloudlfare secondary
	"8.8.8.8",        // Google primary
	"8.8.4.4",        // Google secondary
	"9.9.9.9",        // Quad9 Primary
	"9.9.9.10",       // Quad9 Secondary
	"77.88.8.8",      // Yandex Primary
	"77.88.8.1",      // Yandex Secondary
	"208.67.222.222", // OpenDNS Primary
	"208.67.220.220", // OpenDNS Secondary
}

// Resolver is a struct for resolving DNS names
type Resolver struct {
	resolvers []string
	rand      *rand.Rand
}

// New creates a new resolver struct with the default resolvers
func New() *Resolver {
	return &Resolver{
		resolvers: []string{},
		rand:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// AppendResolversFromFile appends the resolvers read from a file to the list of resolvers
func (r *Resolver) AppendResolversFromFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		r.resolvers = append(r.resolvers, text)
	}
	f.Close()
	return scanner.Err()
}

// AppendResolversFromSlice appends the slice to the list of resolvers
func (r *Resolver) AppendResolversFromSlice(list []string) {
	r.resolvers = append(r.resolvers, list...)
}
