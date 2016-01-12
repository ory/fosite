package explicit

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	authorize "github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestHandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeExplicitStorage(ctrl)
	chgen := internal.NewMockEnigma(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	aresp := internal.NewMockAccessResponder(ctrl)
	//mockcl := internal.NewMockClient(ctrl)
	defer ctrl.Finish()

	h := AuthorizeExplicitEndpointHandler{
		Store:  store,
		Enigma: chgen,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("13245678")
			},
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, errors.New("foo"))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				areq.EXPECT().GetClient().Return(&client.SecureClient{})

				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)

				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				areq.EXPECT().GetClient().Return(&client.SecureClient{})

				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)

				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				store.EXPECT().DeleteAuthorizeCodeSession(gomock.Any()).Return(nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)

				store.EXPECT().DeleteAuthorizeCodeSession(gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().CreateRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")
				areq.EXPECT().GetScopes()
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)

				aresp.EXPECT().SetAccessToken(gomock.Eq("."))
				aresp.EXPECT().SetTokenType(gomock.Eq("bearer"))
				aresp.EXPECT().SetExtra(gomock.Eq("refresh_token"), gomock.Any())
				aresp.EXPECT().SetExtra(gomock.Eq("expires_in"), gomock.Any())
				aresp.EXPECT().SetExtra(gomock.Eq("state"), gomock.Any())
				aresp.EXPECT().SetExtra(gomock.Eq("scope"), gomock.Any())

				store.EXPECT().DeleteAuthorizeCodeSession(gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().CreateRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
		},
	} {
		c.mock()
		err := h.HandleTokenEndpointRequest(nil, c.req, areq, aresp, nil)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func TestValidateTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeExplicitStorage(ctrl)
	chgen := internal.NewMockEnigma(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	authreq := internal.NewMockAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	h := AuthorizeExplicitEndpointHandler{
		Store:  store,
		Enigma: chgen,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("13245678") // grant_type REQUIRED. Value MUST be set to "authorization_code".
			},
		},
		{
			req: &http.Request{
				PostForm: url.Values{"foo": {"bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{"code": {".bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{"code": {"."}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{"code": {"foo.bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(errors.New("foo"))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{"code": {"foo.bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(nil, pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{"code": {"foo.bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			// clients mismatch
			req: &http.Request{
				PostForm: url.Values{"code": {"foo.bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().AnyTimes().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				areq.EXPECT().SetScopes(gomock.Any())
				authreq.EXPECT().GetClient().Return(&client.SecureClient{ID: "bar"})
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{
					"code": {"foo.bar"}, // code REQUIRED. The authorization code received from the authorization server.
				},
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().AnyTimes().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Do(func(_ interface{}, sess *authorize.AuthorizeSession) {
					sess.RequestRedirectURI = "request-redir"
				}).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				areq.EXPECT().SetScopes(gomock.Any())
				authreq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{
					"code":         {"foo.bar"}, // code REQUIRED. The authorization code received from the authorization server.
					"redirect_uri": {"request-redir"},
				},
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().AnyTimes().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Do(func(_ interface{}, sess *authorize.AuthorizeSession) {
					sess.RequestRedirectURI = "request-redir"
				}).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				areq.EXPECT().SetScopes(gomock.Any())
				authreq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
				authreq.EXPECT().GetRequestedAt().Return(time.Now().Add(-time.Hour))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{
					"code":         {"foo.bar"}, // code REQUIRED. The authorization code received from the authorization server.
					"redirect_uri": {"request-redir"},
				},
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().AnyTimes().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				areq.EXPECT().SetScopes(gomock.Any())
				authreq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
				authreq.EXPECT().GetRequestedAt().Return(time.Now().Add(-time.Hour))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{
					"code": {"foo.bar"}, // code REQUIRED. The authorization code received from the authorization server.
				},
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetClient().AnyTimes().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateChallenge(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				areq.EXPECT().SetScopes(gomock.Any())
				authreq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
				authreq.EXPECT().GetRequestedAt().Return(time.Now().Add(time.Hour))
				areq.EXPECT().SetGrantTypeHandled("authorization_code")
			},
		},
	} {
		c.mock()
		err := h.ValidateTokenEndpointRequest(nil, c.req, areq, nil)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
