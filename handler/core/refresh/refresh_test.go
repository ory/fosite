package refresh

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
				areq.EXPECT().GetGrantType().Return("")
			},
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New(""))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetRefreshTokenSession("signature", gomock.Any()).Return(nil, pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any()).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				areq.EXPECT().GetClient().Return(&client.SecureClient{ID: "foo"})
				chgen.EXPECT().ValidateRefreshToken("", gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any()).Return(&fosite.Request{Client: &client.SecureClient{ID: ""}}, nil)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
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
	areq := internal.NewMockAccessRequester(ctrl)
	aresp := internal.NewMockAccessResponder(ctrl)
	//mockcl := internal.NewMockClient(ctrl)
	defer ctrl.Finish()

	areq.EXPECT().GetClient().AnyTimes().Return(&client.SecureClient{})

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
				areq.EXPECT().GetGrantType().Return("")
			},
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				acts.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				acts.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "access", nil)
				rcts.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "refresh", nil)
				store.EXPECT().CreateAccessTokenSession("access", gomock.Any()).Return(nil)
				store.EXPECT().CreateRefreshTokenSession("refresh", gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				acts.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "access", nil)
				rcts.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "refresh", nil)
				rcts.EXPECT().ValidateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().CreateAccessTokenSession("access", gomock.Any()).Return(nil)
				store.EXPECT().CreateRefreshTokenSession("refresh", gomock.Any()).Return(nil)
				store.EXPECT().DeleteRefreshTokenSession(gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("refresh_token")
				acts.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("access.token", "access", nil)
				rcts.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("refresh.token", "refresh", nil)
				rcts.EXPECT().ValidateRefreshToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signature", nil)
				store.EXPECT().CreateAccessTokenSession("access", gomock.Any()).Return(nil)
				store.EXPECT().CreateRefreshTokenSession("refresh", gomock.Any()).Return(nil)
				store.EXPECT().DeleteRefreshTokenSession(gomock.Any()).Return(nil)

				aresp.EXPECT().SetAccessToken("access.token")
				aresp.EXPECT().SetTokenType("bearer")
				aresp.EXPECT().SetExtra("expires_in", gomock.Any())
				aresp.EXPECT().SetExtra("scope", gomock.Any())
				aresp.EXPECT().SetExtra("refresh_token", "refresh.token")
				areq.EXPECT().GetGrantedScopes()
			},
		},
	} {
		c.mock()
		err := h.HandleTokenEndpointRequest(nil, c.req, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
