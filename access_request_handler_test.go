package fosite_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestNewAccessRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	client := internal.NewMockClient(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	fosite := &Fosite{Store: store, Hasher: hasher}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		{
			header:    http.Header{},
			expectErr: ErrInvalidRequest,
			method:    "POST",
			mock:      func() {},
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock:      func() {},
			expectErr: ErrInvalidRequest,
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
				"client_id":  {"foo"},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "GET",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrServerError,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ *http.Request, a AccessRequester) {
					a.SetScopes([]string{"asdfasdf"})
				}).Return(nil)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrInvalidScope,
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ *http.Request, a AccessRequester) {
					a.SetScopes([]string{DefaultMandatoryScope})
				}).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
	} {
		r := &http.Request{
			Header:   c.header,
			PostForm: c.form,
			Form:     c.form,
			Method:   c.method,
		}
		c.mock()
		ctx := NewContext()
		fosite.TokenEndpointHandlers = c.handlers
		ar, err := fosite.NewAccessRequest(ctx, r, &struct{}{})
		is := errors.Is(c.expectErr, err)
		assert.True(t, is, "%d\nwant: %s \ngot: %s", k, c.expectErr, err)
		if !is {
			t.Logf("Error occured: %s", err.(*errors.Error).ErrorStack())
		}
		if err == nil {
			pkg.AssertObjectKeysEqual(t, c.expect, ar, "GrantTypes", "Client")
			assert.NotNil(t, ar.GetRequestedAt())
		}
		t.Logf("Passed test case %d", k)
	}
}

func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
}
