package oauth2

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestResourceOwnerFlow_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	httpreq := &http.Request{PostForm: url.Values{}}

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		ResourceOwnerPasswordCredentialsGrantStorage: store,
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenLifespan: time.Hour,
		},
		ScopeStrategy: fosite.HierarchicScopeStrategy,
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
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{""})
			},
		},
		{
			description: "should fail because because invalid credentials",
			setup: func() {
				httpreq.PostForm.Set("username", "peter")
				httpreq.PostForm.Set("password", "pan")

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"password"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"password"},
				})
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(fosite.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because because error on lookup",
			setup: func() {
				httpreq.PostForm.Set("username", "peter")
				httpreq.PostForm.Set("password", "pan")

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"password"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"password"},
				})
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				httpreq.PostForm.Set("username", "peter")
				httpreq.PostForm.Set("password", "pan")

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"password"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"password"},
				})
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(nil)
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					Scopes: []string{"foo", "bar", "baz"},
				})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar"})
				areq.EXPECT().GetSession().Return(new(fosite.DefaultSession))
				areq.EXPECT().GetRequestForm().Return(url.Values{})
			},
		},
	} {
		c.setup()
		err := h.HandleTokenEndpointRequest(nil, httpreq, areq)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func TestResourceOwnerFlow_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	rtstr := internal.NewMockRefreshTokenStrategy(ctrl)
	aresp := fosite.NewAccessResponse()
	mockAT := "accesstoken.foo.bar"
	mockRT := "refreshtoken.bar.foo"
	defer ctrl.Finish()

	areq := fosite.NewAccessRequest(nil)
	httpreq := &http.Request{PostForm: url.Values{}}

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		ResourceOwnerPasswordCredentialsGrantStorage: store,
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			AccessTokenLifespan: time.Hour,
		},
		RefreshTokenStrategy: rtstr,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
		expect      func()
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			description: "should pass",
			setup: func() {
				areq.Session = &fosite.DefaultSession{}
				areq.GrantTypes = fosite.Arguments{"password"}
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", areq).Return(nil)
			},
			expect: func() {
				assert.Nil(t, aresp.GetExtra("refresh_token"), "unexpected refresh token")
			},
		},
		{
			description: "should pass - offline scope",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"password"}
				areq.GrantScope("offline")
				rtstr.EXPECT().GenerateRefreshToken(nil, areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(nil, "bar", areq).Return(nil)
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", areq).Return(nil)
			},
			expect: func() {
				assert.NotNil(t, aresp.GetExtra("refresh_token"), "expected refresh token")
			},
		},
	} {
		c.setup()
		err := h.PopulateTokenEndpointResponse(nil, httpreq, areq, aresp)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		if c.expect != nil {
			c.expect()
		}
		t.Logf("Passed test case %d", k)
	}
}
