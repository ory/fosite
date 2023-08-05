// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"net/http"

	"github.com/ory/fosite"
	"github.com/ory/x/otelx"
	"go.opentelemetry.io/otel/trace"
)

type InstrumentedFosite struct {
	*fosite.Fosite
}

func (f *InstrumentedFosite) NewAccessRequest(ctx context.Context, r *http.Request, session fosite.Session) (_ fosite.AccessRequester, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewAccessRequest")
	defer otelx.End(span, &err)
	return f.Fosite.NewAccessRequest(ctx, r, session)
}

func (f *InstrumentedFosite) NewAccessResponse(ctx context.Context, requester fosite.AccessRequester) (_ fosite.AccessResponder, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewAccessResponse")
	defer otelx.End(span, &err)

	return f.Fosite.NewAccessResponse(ctx, requester)
}

func (f *InstrumentedFosite) NewAuthorizeRequest(ctx context.Context, r *http.Request) (_ fosite.AuthorizeRequester, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewAuthorizeRequest")
	defer otelx.End(span, &err)

	return f.Fosite.NewAuthorizeRequest(ctx, r)
}

func (f *InstrumentedFosite) NewAuthorizeResponse(ctx context.Context, ar fosite.AuthorizeRequester, session fosite.Session) (_ fosite.AuthorizeResponder, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewAuthorizeResponse")
	defer otelx.End(span, &err)

	return f.Fosite.NewAuthorizeResponse(ctx, ar, session)
}

func (f *InstrumentedFosite) NewPushedAuthorizeRequest(ctx context.Context, r *http.Request) (_ fosite.AuthorizeRequester, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewPushedAuthorizeRequest")
	defer otelx.End(span, &err)

	return f.Fosite.NewPushedAuthorizeRequest(ctx, r)
}

func (f *InstrumentedFosite) NewPushedAuthorizeResponse(ctx context.Context, ar fosite.AuthorizeRequester, session fosite.Session) (_ fosite.PushedAuthorizeResponder, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewPushedAuthorizeResponse")
	defer otelx.End(span, &err)

	return f.Fosite.NewPushedAuthorizeResponse(ctx, ar, session)
}

func (f *InstrumentedFosite) NewRevocationRequest(ctx context.Context, r *http.Request) (err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewRevocationRequest")
	defer otelx.End(span, &err)

	return f.Fosite.NewRevocationRequest(ctx, r)
}
