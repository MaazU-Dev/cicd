package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers   http.Header
		wantKey   string
		wantError error
	}{
		"no authorization header": {
			headers:   http.Header{},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		"empty authorization header": {
			headers:   http.Header{"Authorization": {""}},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		"malformed header missing scheme": {
			headers:   http.Header{"Authorization": {"singlevalue"}},
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		"wrong scheme (Bearer instead of ApiKey)": {
			headers:   http.Header{"Authorization": {"Bearer some-token"}},
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		"valid ApiKey header": {
			headers:   http.Header{"Authorization": {"ApiKey my-secret-key"}},
			wantKey:   "my-secret-key",
			wantError: nil,
		},
		"valid ApiKey header with extra spaces": {
			headers:   http.Header{"Authorization": {"ApiKey key with spaces"}},
			wantKey:   "key",
			wantError: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tc.wantKey)
			}

			if tc.wantError == nil && gotErr != nil {
				t.Errorf("unexpected error: %v", gotErr)
			} else if tc.wantError != nil {
				if gotErr == nil {
					t.Errorf("expected error %q, got nil", tc.wantError)
				} else if gotErr.Error() != tc.wantError.Error() {
					t.Errorf("got error %q, want %q", gotErr, tc.wantError)
				}
			}
		})
	}
}
