package pkce

import "regexp"

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

// IsValid checks if code validates the corresponding regexp
func IsValid(codeChallenge string) bool {
	return pkceMatcher.MatchString(codeChallenge)
}
