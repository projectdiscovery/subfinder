package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateOptionsTimeouts(t *testing.T) {
	tests := []struct {
		name    string
		timeout int
		maxTime int
		wantErr string
	}{
		{name: "positive durations", timeout: 1, maxTime: 1},
		{name: "zero timeout", timeout: 0, maxTime: 1, wantErr: "timeout must be positive"},
		{name: "negative timeout", timeout: -1, maxTime: 1, wantErr: "timeout must be positive"},
		{name: "zero max time", timeout: 1, maxTime: 0, wantErr: "max-time must be positive"},
		{name: "negative max time", timeout: 1, maxTime: -1, wantErr: "max-time must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := Options{
				Domain:             []string{"example.com"},
				Threads:            1,
				Timeout:            tt.timeout,
				MaxEnumerationTime: tt.maxTime,
			}
			err := options.validateOptions()
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
