package fosite

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/client"
	"golang.org/x/net/context"
	"net/http"
)

type AccessRequester interface{}

type AccessRequest struct {
	GrantType string
	Client    client.Client
}

func NewAccessRequest() *AccessRequest {
	return &AccessRequest{}
}

//
// Implements
// * https://tools.ietf.org/html/rfc6749#section-2.3.1
//   Clients in possession of a client password MAY use the HTTP Basic
//   authentication scheme as defined in [RFC2617] to authenticate with
//   the authorization server.  The client identifier is encoded using the
//   "application/x-www-form-urlencoded" encoding algorithm per
//   Appendix B, and the encoded value is used as the username; the client
//   password is encoded using the same algorithm and used as the
//   password.  The authorization server MUST support the HTTP Basic
//   authentication scheme for authenticating clients that were issued a
//   client password.
//   Including the client credentials in the request-body using the two
//   parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
//   to directly utilize the HTTP Basic authentication scheme (or other
//   password-based HTTP authentication schemes).  The parameters can only
//   be transmitted in the request-body and MUST NOT be included in the
//   request URI.
func (c *Fosite) NewAccessRequest(_ context.Context, r *http.Request) (AccessRequester, error) {
	ar := NewAccessRequest()
	r.ParseForm()

	ar.GrantType = r.Form.Get("grant_type")
	if ar.GrantType == "" {
		return ar, errors.New(ErrInvalidRequest)
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return ar, errors.New(ErrInvalidRequest)
	}

	client, err := c.Store.GetClient(clientID)
	if err != nil {
		return ar, errors.New(ErrInvalidClient)
	}

	// Spec doesn't specify if all extension grants should require authorization as well. But we will
	// assume that they do for now.
	if !client.CompareSecretWith([]byte(r.Form.Get(clientSecret))) {
		return ar, errors.New(ErrInvalidClient)
	}

	ar.Client = client

	return ar, nil
}

func (c *Fosite) LoadAccessRequestSession(ctx context.Context, ar AccessRequester, r *http.Request, session interface{}) error {
	for _, loader := range c.TokenEndpointSessionLoaders {
		if err := loader.LoadTokenEndpointSession(ctx, ar, r, session); err != nil {
			return err
		}
	}
	return nil
}
