package auth

import (
	"net/http"
	"testing"
)

func makeHeaders(key, value string) http.Header {
	headers := make(http.Header)
	headers.Set(key, value)
	return headers
}

func TestGetAPIKey(t *testing.T) {

	tests := map[string]struct {
		input     http.Header
		outputVal string
		outputErr error
	}{
		"normal": {
			input:     makeHeaders("Authorization", "ApiKey theKey"),
			outputVal: "theKey",
			outputErr: nil,
		},
		"space_in_value": {
			input:     makeHeaders("Authorization", "ApiKey the Key"),
			outputVal: "the",
			outputErr: nil,
		},
		"no_auth_header": {
			input:     make(http.Header),
			outputVal: "",
			outputErr: ErrNoAuthHeaderIncluded,
		},
		"invalid_auth_key": {
			input:     makeHeaders("Authorize", "ApiKey theKey"),
			outputVal: "",
			outputErr: ErrNoAuthHeaderIncluded,
		},
		"no_ApiKey_in_value": {
			input:     makeHeaders("Authorization", "Key"),
			outputVal: "",
			outputErr: ErrLengthTooLongOrMissingApiKey,
		},
		"ApiKey_invalid_format_in_value": {
			input:     makeHeaders("Authorization", "apikey theKey"),
			outputVal: "",
			outputErr: ErrLengthTooLongOrMissingApiKey,
		},
		"missing_key": {
			input:     makeHeaders("Authorization", "apikey "),
			outputVal: "",
			outputErr: ErrLengthTooLongOrMissingApiKey,
		},
	}

	for name, tc := range tests {
		val, err := GetAPIKey(tc.input)
		if val != tc.outputVal {
			t.Fatalf("Test: %s failed: expected %s, got %s", name, tc.outputVal, val)
		}
		if err != tc.outputErr {
			t.Fatalf("Test: %s failed: expected %s, got %s", name, tc.outputErr, err)
		}
	}
}
