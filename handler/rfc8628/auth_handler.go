// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

// MaxAttempts for retrying the generation of user codes.
const MaxAttempts = 3

// DeviceAuthHandler is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
type DeviceAuthHandler struct {
	Storage  RFC8628CoreStorage
	Strategy RFC8628CodeStrategy
	Config   interface {
		fosite.DeviceProvider
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

// HandleDeviceEndpointRequest implements https://tools.ietf.org/html/rfc8628#section-3.1
func (d *DeviceAuthHandler) HandleDeviceEndpointRequest(ctx context.Context, dar fosite.DeviceRequester, resp fosite.DeviceResponder) error {
	var err error

	var deviceCode string
	deviceCode, err = d.handleDeviceCode(ctx, dar)
	if err != nil {
		return err
	}

	var userCode string
	userCode, err = d.handleUserCode(ctx, dar)
	if err != nil {
		return err
	}

	// Populate the response fields
	resp.SetDeviceCode(deviceCode)
	resp.SetUserCode(userCode)
	resp.SetVerificationURI(d.Config.GetDeviceVerificationURL(ctx))
	resp.SetVerificationURIComplete(d.Config.GetDeviceVerificationURL(ctx) + "?user_code=" + userCode)
	resp.SetExpiresIn(int64(time.Until(dar.GetSession().GetExpiresAt(fosite.UserCode)).Seconds()))
	resp.SetInterval(int(d.Config.GetDeviceAuthTokenPollingInterval(ctx).Seconds()))
	return nil
}

func (d *DeviceAuthHandler) handleDeviceCode(ctx context.Context, dar fosite.DeviceRequester) (string, error) {
	code, signature, err := d.Strategy.GenerateDeviceCode(ctx)
	if err != nil {
		return "", errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	dar.GetSession().SetExpiresAt(fosite.DeviceCode, time.Now().UTC().Add(d.Config.GetDeviceAndUserCodeLifespan(ctx)))
	if err = d.Storage.CreateDeviceCodeSession(ctx, signature, dar.Sanitize(nil)); err != nil {
		return "", errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return code, nil
}

func (d *DeviceAuthHandler) handleUserCode(ctx context.Context, dar fosite.DeviceRequester) (string, error) {
	var err error
	var userCode, signature string
	// Retry when persisting user code fails
	// Possible causes include database connection issue, constraints violations, etc.
	for i := 0; i < MaxAttempts; i++ {
		userCode, signature, err = d.Strategy.GenerateUserCode(ctx)
		if err != nil {
			return "", err
		}

		dar.GetSession().SetExpiresAt(fosite.UserCode, time.Now().UTC().Add(d.Config.GetDeviceAndUserCodeLifespan(ctx)).Round(time.Second))
		if err = d.Storage.CreateUserCodeSession(ctx, signature, dar.Sanitize(nil)); err == nil {
			return userCode, nil
		}
	}

	errMsg := fmt.Sprintf("Exceeded user-code generation max attempts %v: %s", MaxAttempts, err.Error())
	return "", errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(errMsg))
}
