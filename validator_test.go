package fosite_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	store "github.com/ory-am/fosite/fosite-example/pkg"
	"github.com/ory-am/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestValidate(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := internal.NewMockTokenValidator(ctrl)
	defer ctrl.Finish()

	f := compose.ComposeAllEnabled(new(compose.Config), store.NewStore(), []byte{}, nil).(*Fosite)
	httpreq := &http.Request{
		Header: http.Header{
			"Authorization": []string{"bearer some-token"},
		},
		Form: url.Values{},
	}

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
				f.TokenValidators = TokenValidators{validator}
				validator.EXPECT().ValidateToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrUnknownRequest)
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				validator.EXPECT().ValidateToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidClient)
			},
			expectErr: ErrInvalidClient,
		},
		{
			description: "should pass",
			setup: func() {
				validator.EXPECT().ValidateToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, accessRequest AccessRequester, _ []string) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
		{
			description: "should pass",
			scopes:      []string{"bar"},
			setup: func() {
				validator.EXPECT().ValidateToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, accessRequest AccessRequester, _ []string) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
	} {
		c.setup()
		_, err := f.ValidateToken(nil, AccessTokenFromRequest(httpreq), AccessToken, nil, c.scopes...)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
