package fosite_test

import (
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/generator"
	. "github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorizeWorkflow(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	gen := NewMockGenerator(ctrl)
	defer ctrl.Finish()

	redir, _ := url.Parse("http://foo.bar/cb")

	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequester
	}{
		{
			desc: "should pass",
			conf: &Fosite{
				Store: store,
				AuthorizeCodeGenerator: gen,
				AllowedResponseTypes:   []string{"code", "token"},
				Lifetime:               3600,
			},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code token"},
				"state":         []string{"strong-state"},
				"scope":         []string{"foo bar"},
			},
			mock: func() {
				gen.EXPECT().Generate().Return(&generator.Token{Key: "foo", Signature: "bar"}, nil)
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
			expect: &AuthorizeRequester{
				RedirectURI:   redir,
				Client:        &SecureClient{ID: "1234", RedirectURIs: []string{"http://foo.bar/cb"}},
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Scopes:        []string{"foo", "bar"},
				ExpiresIn:     3600,
				Code:          &generator.Token{Key: "foo", Signature: "bar"},
			},
		},
	} {
		c.mock()
		if c.r == nil {
			c.r = &http.Request{Header: http.Header{}}
			if c.query != nil {
				c.r.URL = &url.URL{RawQuery: c.query.Encode()}
			}
		}

		// equals to: c.conf = NewDefaultOAuth2(store)
		c.conf.Store = store
		authorizeRequest, err := c.conf.NewAuthorizeRequest(context.Background(), c.r)
		require.Nil(t, err, "%d: %s", k, err)

		userID := "user-id"
		_ = NewAuthorizeSessionSQL(authorizeRequest, userID)

		// 	if err := store.StoreAuthorizeSession(sess); err != nil {
		// 		return err
		// 	}

		//response := NewAuthorizeResponse()
		// err = oauth2.HandleResponseTypes(authorizeRequest, response, session)
		// err = alsoHandleMyCustomResponseType(authorizeRequest, response, "fancyArguments", 1234)
		//
		// or
		//
		// this approach would make it possible to check if all response types could be served or not
		// additionally, a callback for FinishAccessRequest could be provided
		//
		// response = &AuthorizeResponse{}
		// oauth2.RegisterResponseTypeHandler("custom_type", alsoHandleMyCustomResponseType)
		// err = oauth2.HandleResponseTypes(authorizeRequest, response, session)
		// ****

		// Almost done! The next step is going to persist the session in the database for later use.
		// It is additionally going to output a result based on response_type.

		// ** API not finalized yet **
		// err := oauth2.FinishAuthorizeRequest(rw, response, session)
		// ****
	}
}
