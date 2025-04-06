package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API key",
			headers:       http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed header - wrong scheme",
			headers:       http.Header{"Authorization": []string{"Bearer something"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Malformed header - incomplete value",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Malformed header - empty value",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "FAIL",
			expectedError: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if err == nil && tt.expectedError != nil {
				t.Errorf("expected error %q, got nil", tt.expectedError)
			} else if err != nil && tt.expectedError == nil {
				t.Errorf("unexpected error: %q", err)
			} else if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("expected error %q, got %q", tt.expectedError, err)
			}
		})
	}
}
