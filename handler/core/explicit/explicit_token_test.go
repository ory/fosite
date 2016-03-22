package explicit

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
)

func TestPopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeCodeGrantStorage(ctrl)
	ach := internal.NewMockAccessTokenStrategy(ctrl)
	rch := internal.NewMockRefreshTokenStrategy(ctrl)
	auch := internal.NewMockAuthorizeCodeStrategy(ctrl)
	aresp := internal.NewMockAccessResponder(ctrl)
	//mockcl := internal.NewMockClient(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAccessRequest(nil)
	httpreq := &http.Request{PostForm: url.Values{}}

	h := AuthorizeExplicitGrantTypeHandler{
		AuthorizeCodeGrantStorage: store,
		AuthorizeCodeStrategy:     auch,
		AccessTokenStrategy:       ach,
		RefreshTokenStrategy:      rch,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"123"}
			},
		},
		{
			description: "should fail because authcode validation failed",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"authorization_code"}
				httpreq.PostForm.Add("code", "authcode")
				auch.EXPECT().ValidateAuthorizeCode(nil, "authcode", httpreq, areq).Return("", errors.New(""))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because access token generation failed",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"authorization_code"}
				httpreq.PostForm.Add("code", "authcode")
				auch.EXPECT().ValidateAuthorizeCode(nil, "authcode", httpreq, areq).AnyTimes().Return("authsig", nil)
				ach.EXPECT().GenerateAccessToken(nil, httpreq, areq).Return("", "", errors.New("error"))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because refresh token generation failed",
			setup: func() {
				ach.EXPECT().GenerateAccessToken(nil, httpreq, areq).AnyTimes().Return("access.ats", "ats", nil)
				rch.EXPECT().GenerateRefreshToken(nil, httpreq, areq).Return("", "", errors.New("error"))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because persisting failed",
			setup: func() {
				rch.EXPECT().GenerateRefreshToken(nil, httpreq, areq).AnyTimes().Return("refresh.rts", "rts", nil)
				store.EXPECT().PersistAuthorizeCodeGrantSession(nil, "authsig", "ats", "rts", areq).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				areq.GrantedScopes = fosite.Arguments{"foo"}
				store.EXPECT().PersistAuthorizeCodeGrantSession(nil, "authsig", "ats", "rts", areq).Return(nil)

				aresp.EXPECT().SetAccessToken("access.ats")
				aresp.EXPECT().SetTokenType("bearer")
				aresp.EXPECT().SetExtra("refresh_token", "refresh.rts")
				aresp.EXPECT().SetExpiresIn(gomock.Any())
				aresp.EXPECT().SetScopes(areq.GrantedScopes)
			},
		},
	} {
		c.setup()
		err := h.PopulateTokenEndpointResponse(nil, httpreq, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func TestHandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeCodeGrantStorage(ctrl)
	ach := internal.NewMockAuthorizeCodeStrategy(ctrl)
	defer ctrl.Finish()

	authreq := fosite.NewAuthorizeRequest()
	areq := fosite.NewAccessRequest(nil)
	httpreq := &http.Request{PostForm: url.Values{}}

	h := AuthorizeExplicitGrantTypeHandler{
		AuthorizeCodeGrantStorage: store,
		AuthorizeCodeStrategy:     ach,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"12345678"} // grant_type REQUIRED. Value MUST be set to "authorization_code".
			},
		},
		{
			description: "should fail because authcode validation failed",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"authorization_code"} // grant_type REQUIRED. Value MUST be set to "authorization_code".
				httpreq.PostForm = url.Values{"code": {"foo.bar"}}
				ach.EXPECT().ValidateAuthorizeCode(nil, "foo.bar", httpreq, areq).Return("", errors.New(""))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because authcode could not be retrieved (1)",
			setup: func() {
				ach.EXPECT().ValidateAuthorizeCode(nil, "foo.bar", httpreq, areq).AnyTimes().Return("bar", nil)
				store.EXPECT().GetAuthorizeCodeSession(nil, "bar", nil).Return(nil, pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because authcode could not be retrieved (2)",
			setup: func() {
				store.EXPECT().GetAuthorizeCodeSession(nil, "bar", nil).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because client mismatch",
			setup: func() {
				store.EXPECT().GetAuthorizeCodeSession(nil, "bar", nil).AnyTimes().Return(authreq, nil)

				areq.Client = &client.SecureClient{ID: "foo"}
				authreq.Scopes = fosite.Arguments{"a", "b"}
				authreq.Client = &client.SecureClient{ID: "bar"}
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because redirect uri not provided",
			setup: func() {
				authreq.Form.Add("redirect_uri", "request-redir")
				authreq.Client = &client.SecureClient{ID: "foo"}
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because expired",
			setup: func() {
				httpreq.PostForm.Add("redirect_uri", "request-redir")
				authreq.RequestedAt = time.Now().Add(-time.Hour * 24)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should pass (1)",
			setup: func() {
				authreq.RequestedAt = time.Now().Add(-time.Hour * 24)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should pass (2)",
			setup: func() {
				httpreq.PostForm = url.Values{"code": []string{"foo.bar"}}
				authreq.Form.Del("redirect_uri")
				authreq.RequestedAt = time.Now().Add(time.Hour)
			},
		},
	} {
		c.setup()
		err := h.HandleTokenEndpointRequest(nil, httpreq, areq)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
