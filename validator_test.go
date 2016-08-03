package fosite_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/fosite-example/store"
	"github.com/ory-am/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestValidate(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := internal.NewMockAuthorizedRequestValidator(ctrl)
	defer ctrl.Finish()

	f := NewFosite(store.NewStore())
	httpreq := &http.Request{Form: url.Values{}}

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
				f.AuthorizedRequestValidators = AuthorizedRequestValidators{validator}
				validator.EXPECT().ValidateRequest(nil, httpreq, gomock.Any()).Return(ErrUnknownRequest)
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				validator.EXPECT().ValidateRequest(nil, httpreq, gomock.Any()).Return(ErrInvalidClient)
			},
			expectErr: ErrInvalidClient,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				validator.EXPECT().ValidateRequest(nil, httpreq, gomock.Any()).Do(func(ctx context.Context, req *http.Request, accessRequest AccessRequester) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
			expectErr: ErrRequestForbidden,
		},
		{
			description: "should pass",
			setup: func() {
				validator.EXPECT().ValidateRequest(nil, httpreq, gomock.Any()).Do(func(ctx context.Context, req *http.Request, accessRequest AccessRequester) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
		{
			description: "should pass",
			scopes:      []string{"bar"},
			setup: func() {
				validator.EXPECT().ValidateRequest(nil, httpreq, gomock.Any()).Do(func(ctx context.Context, req *http.Request, accessRequest AccessRequester) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
	} {
		c.setup()
		_, err := f.Validate(nil, httpreq, nil, c.scopes...)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
