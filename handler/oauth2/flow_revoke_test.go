package oauth2

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestRevokeToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockTokenRevocationStorage(ctrl)
	defer ctrl.Finish()

	h := TokenRevocationHandler{
		TokenRevocationStorage: store,
	}

	var token string
	var tokenType fosite.TokenType

	for k, c := range []struct {
		description string
		mock        func()
		expectErr   error
	}{
		{
			description: "should pass - refresh token first",
			expectErr:   nil,
			mock: func() {
				token = "foo"
				tokenType = fosite.RefreshToken
				store.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().AccessTokenSignature(token)
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - access token first",
			expectErr:   nil,
			mock: func() {
				token = "foo"
				tokenType = fosite.AccessToken
				store.EXPECT().AccessTokenSignature(token)
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
				store.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
			},
		},
	} {
		c.mock()
		err := h.RevokeToken(nil, token, tokenType)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
