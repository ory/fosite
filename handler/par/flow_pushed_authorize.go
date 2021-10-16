package par

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/x/errorsx"
)

const (
	defaultPARKeyLength = 32
)

var b64 = base64.URLEncoding.WithPadding(base64.NoPadding)

type PushedAuthorizeHandler struct {
	Storage                  PARStorage
	PARContextLifetime       time.Duration
	RequestURIPrefix         string
	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy

	IsRedirectURISecure func(*url.URL) bool
}

// HandlePushedAuthorizeRequest handles a pushed authorize endpoint request. To extend the handler's capabilities, the http request
// is passed along, if further information retrieval is required. If the handler feels that he is not responsible for
// the pushed authorize request, he must return nil and NOT modify session nor responder neither requester.
//
func (c *PushedAuthorizeHandler) HandlePushedAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.PushedAuthorizeResponder) error {
	if !ar.GetResponseTypes().HasOneOf("token", "code", "id_token") {
		return nil
	}

	if !c.secureChecker()(ar.GetRedirectURI()) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix `localhost`, for example: http://myapp.localhost/."))
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.AudienceMatchingStrategy(client.GetAudience(), ar.GetRequestedAudience()); err != nil {
		return err
	}

	if ar.GetSession() != nil {
		ar.GetSession().SetExpiresAt(fosite.PushedAuthorizeRequestContext, time.Now().UTC().Add(c.PARContextLifetime))
	}

	// generate an ID
	stateKey, err := hmac.RandomBytes(defaultPARKeyLength)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInsufficientEntropy.WithHint("Unable to generate the random part of the request_uri.").WithWrap(err).WithDebug(err.Error()))
	}

	requestURI := fmt.Sprintf("%s%s", c.RequestURIPrefix, b64.EncodeToString(stateKey))
	// store
	if err = c.Storage.CreatePARSession(ctx, requestURI, ar); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithHint("Unable to store the PAR session").WithWrap(err).WithDebug(err.Error()))
	}

	resp.SetRequestURI(requestURI)
	return nil
}

func (c *PushedAuthorizeHandler) secureChecker() func(*url.URL) bool {
	if c.IsRedirectURISecure == nil {
		c.IsRedirectURISecure = fosite.IsRedirectURISecure
	}
	return c.IsRedirectURISecure
}
