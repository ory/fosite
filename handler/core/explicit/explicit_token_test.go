package explicit

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestHandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeCodeGrantStorage(ctrl)
	ach := internal.NewMockAccessTokenStrategy(ctrl)
	rch := internal.NewMockRefreshTokenStrategy(ctrl)
	auch := internal.NewMockAuthorizeCodeStrategy(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	aresp := internal.NewMockAccessResponder(ctrl)
	//mockcl := internal.NewMockClient(ctrl)
	defer ctrl.Finish()

	h := AuthorizeExplicitGrantTypeHandler{
		Store:                store,
		AuthorizeCodeStrategy: auch,
		AccessTokenStrategy:  ach,
		RefreshTokenStrategy: rch,
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
				ach.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", fosite.ErrServerError)
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")
				ach.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", nil)
				rch.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", nil)

				auch.EXPECT().ValidateAuthorizeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)

				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")

				ach.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", nil)
				rch.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", nil)

				auch.EXPECT().ValidateAuthorizeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)

				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")

				ach.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", nil)
				rch.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", nil)

				auch.EXPECT().ValidateAuthorizeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)

				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().CreateRefreshTokenSession(gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code")
				areq.EXPECT().GetGrantedScopes()

				ach.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("access.at", "at", nil)
				rch.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("refresh.rt", "rt", nil)

				auch.EXPECT().ValidateAuthorizeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)

				aresp.EXPECT().SetAccessToken("access.at")
				aresp.EXPECT().SetTokenType("bearer")
				aresp.EXPECT().SetExtra("refresh_token", "refresh.rt")
				aresp.EXPECT().SetExtra("expires_in", gomock.Any())
				aresp.EXPECT().SetExtra("state", gomock.Any())
				aresp.EXPECT().SetExtra("scope", gomock.Any())

				store.EXPECT().DeleteAuthorizeCodeSession(gomock.Any()).Return(nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().CreateRefreshTokenSession(gomock.Any(), gomock.Any()).Return(nil)
			},
		},
	} {
		c.mock()
		err := h.HandleTokenEndpointRequest(nil, c.req, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func TestValidateTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeCodeGrantStorage(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	ach := internal.NewMockAuthorizeCodeStrategy(ctrl)
	authreq := internal.NewMockAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	h := AuthorizeExplicitGrantTypeHandler{
		Store: store,
		AuthorizeCodeStrategy: ach,
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
				PostForm: url.Values{"code": {"foo.bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("foo"))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{"code": {"foo.bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetSession().Return("asdf")
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), "asdf").Return(nil, pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{
				PostForm: url.Values{"code": {"foo.bar"}}, // code REQUIRED. The authorization code received from the authorization server.
			},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("authorization_code") // grant_type REQUIRED. Value MUST be set to "authorization_code".
				areq.EXPECT().GetSession().Return(nil)
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)
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
				areq.EXPECT().GetSession().Return(nil)
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("bar", nil)
				store.EXPECT().GetAuthorizeCodeSession("bar", gomock.Any()).Return(authreq, nil)

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
				areq.EXPECT().GetSession().Return(nil)
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetAuthorizeCodeSession("signature", gomock.Any()).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				authreq.EXPECT().GetRequestForm().Return(url.Values{"redirect_uri": {"request-redir"}})
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
				areq.EXPECT().GetSession().Return(nil)
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(authreq, nil)

				authreq.EXPECT().GetRequestForm().Return(url.Values{"redirect_uri": {"request-redir"}})
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
				areq.EXPECT().GetSession().Return(nil)
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				authreq.EXPECT().GetRequestForm().Return(url.Values{"redirect_uri": {"request-redir"}})
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
				areq.EXPECT().GetSession().Return(nil)
				ach.EXPECT().ValidateAuthorizeCode("foo.bar", gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)
				store.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(authreq, nil)

				authreq.EXPECT().GetScopes().Return([]string{})
				authreq.EXPECT().GetRequestForm().Return(url.Values{})
				areq.EXPECT().SetScopes(gomock.Any())
				authreq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
				authreq.EXPECT().GetRequestedAt().Return(time.Now().Add(time.Hour))
				authreq.EXPECT().GetSession().Return("sess")
				areq.EXPECT().SetSession("sess")
				areq.EXPECT().SetGrantTypeHandled("authorization_code")
			},
		},
	} {
		c.mock()
		err := h.ValidateTokenEndpointRequest(nil, c.req, areq)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
