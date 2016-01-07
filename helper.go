package fosite

import (
	"net/url"
	"strings"
)

func areResponseTypesValid(c *Fosite, responseTypes []string) bool {
	if len(responseTypes) < 1 {
		return false
	}
	for _, responseType := range responseTypes {
		if !StringInSlice(responseType, c.AllowedResponseTypes) {
			return false
		}
	}
	return true
}

func StringInSlice(needle string, haystack []string) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}

func removeEmpty(args []string) (ret []string) {
	for _, v := range args {
		v = strings.TrimSpace(v)
		if v != "" {
			ret = append(ret, v)
		}
	}
	return
}

// rfc6749 3.1.2.  Redirection Endpoint
// "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3"
func validateURL(rawurl string) (purl *url.URL, _ bool) {
	purl, err := url.Parse(rawurl)
	if err != nil {
		return nil, false
	} else if purl.Host == "" {
		return nil, false
	} else if purl.Fragment != "" {
		// "The endpoint URI MUST NOT include a fragment component."
		return nil, false
	}
	return purl, true
}
