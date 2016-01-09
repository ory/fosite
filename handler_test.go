package fosite_test

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"net/http"
	"testing"
)

var arbitraryError = errors.New("")

// Should pass:
//
// * https://tools.ietf.org/html/rfc6749#section-3.1.1
//   response_type REQUIRED.
//   The value MUST be one of "code" for requesting an
//   authorization code as described by Section 4.1.1, "token" for
//   requesting an access token (implicit grant) as described by
//   Section 4.2.1, or a registered extension value as described by Section 8.4.
//
// * https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#rnc
func TestNewAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	rths := []*MockResponseTypeHandler{
		NewMockResponseTypeHandler(ctrl),
		NewMockResponseTypeHandler(ctrl),
	}
	req := NewMockAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	for k, c := range []struct {
		handlers     []ResponseTypeHandler
		mock         func()
		expectsError error
		expects      AuthorizeResponder
	}{
		{
			handlers: []ResponseTypeHandler{
				rths[0],
				rths[1],
			},
			mock: func() {
				rths[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(arbitraryError)
			},
			expectsError: arbitraryError,
		},
		{
			handlers: []ResponseTypeHandler{
				rths[0],
				rths[1],
			},
			mock: func() {
				rths[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidResponseType)
				rths[1].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(arbitraryError)
			},
			expectsError: arbitraryError,
		},
	} {
		c.mock()
		o := &Fosite{
			ResponseTypeHandlers: c.handlers,
		}
		resp, err := o.NewAuthorizeResponse(context.Background(), &http.Request{}, req, nil)
		require.Equal(t, c.expectsError, err, "%d: %s", k, err)
		if err != nil {
			require.Equal(t, c.expects, resp)
		}
		t.Logf("Passed test case %d", k)
	}
}
