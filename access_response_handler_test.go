package fosite_test

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"net/http"
	"testing"
)

func TestNewAccessResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	defer ctrl.Finish()

	f := &Fosite{}
	for k, c := range []struct {
		handlers  TokenEndpointHandlers
		mock      func()
		expectErr error
		expect    AccessResponder
	}{
		{
			mock:      func() {},
			handlers:  TokenEndpointHandlers{},
			expectErr: ErrUnsupportedGrantType,
		},
		{
			mock: func() {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers:  TokenEndpointHandlers{"a": handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers:  TokenEndpointHandlers{"a": handler},
			expectErr: ErrUnsupportedGrantType,
		},
		{
			mock: func() {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ *http.Request, _ AccessRequester, resp AccessResponder, _param4 interface{}) {
					resp.SetAccessToken("foo")
				}).Return(nil)
			},
			handlers:  TokenEndpointHandlers{"a": handler},
			expectErr: ErrUnsupportedGrantType,
		},
		{
			mock: func() {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ *http.Request, _ AccessRequester, resp AccessResponder, _param4 interface{}) {
					resp.SetAccessToken("foo")
					resp.SetTokenType("bar")
				}).Return(nil)
			},
			handlers: TokenEndpointHandlers{"a": handler},
			expect: &AccessResponse{
				Extra:       map[string]interface{}{},
				AccessToken: "foo",
				TokenType:   "bar",
			},
		},
	} {
		f.TokenEndpointHandlers = c.handlers
		c.mock()
		ar, err := f.NewAccessResponse(nil, nil, nil, struct{}{})
		assert.True(t, errors.Is(c.expectErr, err), "%d", k)
		assert.Equal(t, ar, c.expect)
		t.Logf("Passed test case %d", k)
	}
}
