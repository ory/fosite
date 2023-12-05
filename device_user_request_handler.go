// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"net/http"

	"github.com/ory/fosite/i18n"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/otelx"
	"go.opentelemetry.io/otel/trace"
)

func (f *Fosite) NewDeviceUserRequest(ctx context.Context, r *http.Request) (_ DeviceUserRequester, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewDeviceUserRequest")
	defer otelx.End(span, &err)

	return f.newDeviceUserRequest(ctx, r)
}

func (f *Fosite) newDeviceUserRequest(ctx context.Context, r *http.Request) (DeviceUserRequester, error) {
	request := NewDeviceUserRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if err := r.ParseForm(); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Form = r.Form

	verifier := request.GetRequestForm().Get("device_verifier")
	if verifier != "" {
		client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get("client_id"))
		if err != nil {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebug(err.Error()))
		}
		request.Client = client

		if !client.GetGrantTypes().Has(string(GrantTypeDeviceCode)) {
			return nil, errorsx.WithStack(ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
		}
	}

	return request, nil
}
