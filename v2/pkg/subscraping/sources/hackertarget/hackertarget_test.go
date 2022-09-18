package hackertarget_test

import (
	"context"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/stretchr/testify/assert"
)

func TestHackerTargetWithActualDomain(t *testing.T) {
	//given
	ctx := context.Background()
	domain := "projectdiscovery.io"
	keys := &subscraping.Keys{}
	session, err := subscraping.NewSession(domain, keys, "", 0, 10)
	if err != nil {
		t.Fatalf("Expected nil got %v while creating session\n", err)
	}

	hackertarget := hackertarget.Source{}

	//when
	result := <-hackertarget.Run(ctx, domain, session)

	//expect
	assert.NotNil(t, result.Value)
}

func TestHackerTargetWithShortTimeout(t *testing.T) {
	//given
	ctx := context.Background()
	domain := "projectdiscovery.io"
	keys := &subscraping.Keys{}
	session, err := subscraping.NewSession(domain, keys, "", 0, 1)
	if err != nil {
		t.Fatalf("Expected nil got %v while creating session\n", err)
	}

	hackertarget := hackertarget.Source{}

	//when
	result := <-hackertarget.Run(ctx, domain, session)

	//expect
	assert.Equal(t, result.Value, "")
}

func TestHackerTargetWithEmptyDomain(t *testing.T) {
	//given
	ctx := context.Background()
	domain := ""
	keys := &subscraping.Keys{}
	session, err := subscraping.NewSession(domain, keys, "", 0, 10)
	if err != nil {
		t.Fatalf("Expected nil got %v while creating session\n", err)
	}

	hackertarget := hackertarget.Source{}

	//when
	result := <-hackertarget.Run(ctx, domain, session)

	//expect
	assert.Equal(t, result.Value, "")
}
