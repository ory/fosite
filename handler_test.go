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

func TestNewAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	rths := []*MockResponseTypeHandler{
		NewMockResponseTypeHandler(ctrl),
		NewMockResponseTypeHandler(ctrl),
		NewMockResponseTypeHandler(ctrl),
	}
	defer ctrl.Finish()

	for k, c := range []struct {
		handlers     []ResponseTypeHandler
		mock         func()
		expectsError error
		expects      *AuthorizeResponse
	}{
		{
			handlers: []ResponseTypeHandler{
				rths[0],
				rths[1],
			},
			mock: func() {
				rths[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(arbitraryError)
			},
			expectsError: arbitraryError,
		},
		{
			handlers: []ResponseTypeHandler{
				rths[0],
				rths[1],
			},
			mock: func() {
				rths[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidResponseType)
				rths[1].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(arbitraryError)
			},
			expectsError: arbitraryError,
		},
	} {
		c.mock()
		o := &OAuth2{
			ResponseTypeHandlers: c.handlers,
		}
		resp, err := o.NewAuthorizeResponse(context.Background(), &AuthorizeRequest{}, &http.Request{})
		require.Equal(t, c.expectsError, err, "%d: %s", k, err)
		if err != nil {
			require.Equal(t, c.expects, resp)
		}
	}
}
