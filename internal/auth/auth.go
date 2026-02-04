package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")
var ErrLengthTooLongOrMissingApiKey = errors.New("malformed authorization header")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "REMOVE THIS VALUE (On purpose break)", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", ErrLengthTooLongOrMissingApiKey
	}

	return splitAuth[1], nil
}
