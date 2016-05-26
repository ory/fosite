package fosite

import "strings"

// Scopes is a list of scopes.
type Scopes interface {
	// Fulfill returns true if requestScope is fulfilled by the scope list.
	Grant(requestScope string) bool
}

// Client represents a client or an app.
type Client interface {
	// GetID returns the client ID.
	GetID() string

	// GetHashedSecret returns the hashed secret as it is stored in the store.
	GetHashedSecret() []byte

	// Returns the client's allowed redirect URIs.
	GetRedirectURIs() []string

	// Returns the client's allowed grant types.
	GetGrantTypes() Arguments

	// Returns the client's allowed response types.
	GetResponseTypes() Arguments

	// Returns the client's owner.
	GetOwner() string

	// Returns the scopes this client was granted.
	GetGrantedScopes() Scopes
}

// DefaultClient is a simple default implementation of the Client interface.
type DefaultClient struct {
	ID                string   `json:"id" gorethink:"id"`
	Name              string   `json:"client_name" gorethink:"client_name"`
	Secret            []byte   `json:"client_secret,omitempty" gorethink:"client_secret"`
	RedirectURIs      []string `json:"redirect_uris" gorethink:"redirect_uris"`
	GrantTypes        []string `json:"grant_types" gorethink:"grant_types"`
	ResponseTypes     []string `json:"response_types" gorethink:"response_types"`
	GrantedScopes     []string `json:"granted_scopes" gorethink:"granted_scopes"`
	Owner             string   `json:"owner" gorethink:"owner"`
	PolicyURI         string   `json:"policy_uri" gorethink:"policy_uri"`
	TermsOfServiceURI string   `json:"tos_uri" gorethink:"tos_uri"`
	ClientURI         string   `json:"client_uri" gorethink:"client_uri"`
	LogoURI           string   `json:"logo_uri" gorethink:"logo_uri"`
	Contacts          []string `json:"contacts" gorethink:"contacts"`
}

type DefaultScopes struct {
	Scopes []string
}

func (s *DefaultScopes) Grant(requestScope string) bool {
	for _, scope := range s.Scopes {
		// foo == foo -> true
		if scope == requestScope {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(scope) > len(requestScope) {
			continue
		}

		needles := strings.Split(requestScope, ".")
		haystack := strings.Split(scope, ".")
		haystackLen := len(haystack) - 1
		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				continue
			}
		}
	}

	return false
}

func (c *DefaultClient) GetID() string {
	return c.ID
}

func (c *DefaultClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c *DefaultClient) GetHashedSecret() []byte {
	return c.Secret
}

func (c *DefaultClient) GetGrantedScopes() Scopes {
	return &DefaultScopes{
		Scopes: c.GrantedScopes,
	}
}

func (c *DefaultClient) GetGrantTypes() Arguments {
	// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	//
	// JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring
	// that it will restrict itself to using.
	// If omitted, the default is that the Client will use only the authorization_code Grant Type.
	if len(c.GrantTypes) == 0 {
		return Arguments{"authorization_code"}
	}
	return Arguments(c.GrantTypes)
}

func (c *DefaultClient) GetResponseTypes() Arguments {
	// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	//
	// <JSON array containing a list of the OAuth 2.0 response_type values that the Client is declaring
	// that it will restrict itself to using. If omitted, the default is that the Client will use
	// only the code Response Type.
	if len(c.ResponseTypes) == 0 {
		return Arguments{"code"}
	}
	return Arguments(c.ResponseTypes)
}

func (c *DefaultClient) GetOwner() string {
	return c.Owner
}
