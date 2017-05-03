package fosite_test

import (
	"net/http"
	"testing"

	"context"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestAccessTokenFromRequestNoToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	assert.Equal(t, AccessTokenFromRequest(req), "", "No token should produce an empty string")
}

func TestAccessTokenFromRequestHeader(t *testing.T) {
	token := "TokenFromHeader"

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from header")
}

func TestAccessTokenFromRequestQuery(t *testing.T) {
	token := "TokenFromQueryParam"

	req, _ := http.NewRequest("GET", "http://example.com/test?access_token="+token, nil)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from access_token query parameter")
}

func TestIntrospect(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := internal.NewMockTokenIntrospector(ctrl)
	defer ctrl.Finish()

	f := compose.ComposeAllEnabled(new(compose.Config), storage.NewMemoryStore(), []byte{}, nil).(*Fosite)

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add("Authorization", "bearer some-token")

	for k, c := range []struct {
		description string
		scopes      []string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail",
			scopes:      []string{},
			setup: func() {
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				f.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrUnknownRequest)
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidClient)
			},
			expectErr: ErrInvalidClient,
		},
		{
			description: "should pass",
			setup: func() {
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, accessRequest AccessRequester, _ []string) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
		{
			description: "should pass",
			scopes:      []string{"bar"},
			setup: func() {
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, accessRequest AccessRequester, _ []string) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
	} {
		c.setup()
		_, err := f.IntrospectToken(nil, AccessTokenFromRequest(req), AccessToken, nil, c.scopes...)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
