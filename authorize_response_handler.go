package fosite

import (
	"github.com/go-errors/errors"
	"golang.org/x/net/context"
	"net/http"
)

func (c *Fosite) WriteAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder) {
	redir := ar.GetRedirectURI()

	// Explicit grants
	q := redir.Query()
	rq := resp.GetQuery()
	for k := range rq {
		q.Set(k, rq.Get(k))
	}
	redir.RawQuery = q.Encode()

	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := resp.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	// Implicit grants
	redir.Fragment = resp.GetFragment().Encode()

	// https://tools.ietf.org/html/rfc6749#section-4.1.1
	// When a decision is established, the authorization server directs the
	// user-agent to the provided client redirection URI using an HTTP
	// redirection response, or by other means available to it via the
	// user-agent.
	wh.Set("Location", redir.String())
	rw.WriteHeader(http.StatusFound)
}

func (o *Fosite) NewAuthorizeResponse(ctx context.Context, r *http.Request, ar AuthorizeRequester, session interface{}) (AuthorizeResponder, error) {
	if session == nil {
		return nil, errors.New("Session must not be nil")
	}

	var resp = NewAuthorizeResponse()
	for _, h := range o.AuthorizeEndpointHandlers {
		if err := h.HandleAuthorizeEndpointRequest(ctx, resp, ar, r, session); err != nil {
			return nil, err
		}
	}

	if !ar.DidHandleAllResponseTypes() {
		return nil, ErrUnsupportedResponseType
	}

	return resp, nil
}
