package refresh

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
	"gopkg.in/ory-am/fosite.v0"
)

func TestValidateTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockRefreshTokenGrantStorage(ctrl)
	chgen := internal.NewMockRefreshTokenStrategy(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	h := RefreshTokenGrantHandler{
		Store:                store,
		RefreshTokenStrategy: chgen,
		AccessTokenLifespan:  time.Hour,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{""})
			},
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"refresh_token"})
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New(""))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"refresh_token"})
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetRefreshTokenSession("signature", gomock.Any()).Return(nil, pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"refresh_token"})
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any()).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"refresh_token"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any()).Return(&fosite.Request{Client: &client.SecureClient{ID: ""}}, nil)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"refresh_token"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any()).Return(&fosite.Request{Client: &client.SecureClient{ID: "foo"}}, nil)
				areq.EXPECT().SetGrantTypeHandled("refresh_token")
			},
		},
	} {
		c.mock()
		err := h.ValidateTokenEndpointRequest(nil, c.req, areq)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func TestHandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockRefreshTokenGrantStorage(ctrl)
	rcts := internal.NewMockRefreshTokenStrategy(ctrl)
	acts := internal.NewMockAccessTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(nil)
	aresp := internal.NewMockAccessResponder(ctrl)
	httpreq := &http.Request{PostForm: url.Values{}}
	defer ctrl.Finish()

	areq.Client = &client.SecureClient{}
	h := RefreshTokenGrantHandler{
		Store:                store,
		RefreshTokenStrategy: rcts,
		AccessTokenStrategy:  acts,
		AccessTokenLifespan:  time.Hour,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			mock: func() {
				areq.GrantTypes = fosite.Arguments{""}
				rcts.EXPECT().ValidateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				acts.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"refresh_token"}
				rcts.EXPECT().ValidateRefreshToken(gomock.Any(), nil, httpreq, areq).Return("orig-sig", nil)
				acts.EXPECT().GenerateAccessToken(nil, httpreq, areq).Return("access.atsig", "atsig", nil)
				rcts.EXPECT().GenerateRefreshToken(nil, httpreq, areq).Return("refresh.resig", "resig", nil)
				store.EXPECT().PersistAuthorizeCodeGrantSession(nil, "orig-sig", "atsig", "resig", areq).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"refresh_token"}
				rcts.EXPECT().ValidateRefreshToken(gomock.Any(), nil, httpreq, areq).Return("orig-sig", nil)
				acts.EXPECT().GenerateAccessToken(nil, httpreq, areq).Return("access.atsig", "atsig", nil)
				rcts.EXPECT().GenerateRefreshToken(nil, httpreq, areq).Return("refresh.resig", "resig", nil)
				store.EXPECT().PersistAuthorizeCodeGrantSession(nil, "orig-sig", "atsig", "resig", areq).Return(nil)

				aresp.EXPECT().SetAccessToken("access.atsig")
				aresp.EXPECT().SetTokenType("bearer")
				aresp.EXPECT().SetExtra("expires_in", gomock.Any())
				aresp.EXPECT().SetExtra("scope", gomock.Any())
				aresp.EXPECT().SetExtra("refresh_token", "refresh.resig")
			},
		},
	} {
		c.mock()
		err := h.HandleTokenEndpointRequest(nil, httpreq, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
