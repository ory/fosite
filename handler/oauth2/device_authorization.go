package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

// DeviceAuthorizationHandler is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
type DeviceAuthorizationHandler struct {
	DeviceCodeStorage       DeviceCodeStorage
	DeviceCodeStrategy      DeviceCodeStrategy
	UserCodeStrategy        UserCodeStrategy
	DeviceCodeLifespan      time.Duration
	UserCodeLifespan        time.Duration
	DeviceCodeRetryInterval time.Duration
	VerificationURI         string
}

func (d *DeviceAuthorizationHandler) HandleDeviceAuthorizeEndpointRequest(ctx context.Context, dar fosite.Requester, resp fosite.DeviceAuthorizeResponder) error {

	deviceCode, err := d.DeviceCodeStrategy.GenerateDeviceCode()
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	userCode, err := d.UserCodeStrategy.GenerateUserCode()
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Set User Code expiry time
	dar.GetSession().SetExpiresAt(fosite.UserCode, time.Now().UTC().Add(d.UserCodeLifespan).Round(time.Second))
	dar.SetID(deviceCode)

	// Store the User Code session (this has no real data other that the uer and deviuce code), can be converted into a 'full' session after user auth
	if err := d.DeviceCodeStorage.CreateUserCodeSession(ctx, userCode, dar); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Populate the response fields
	resp.SetDeviceCode(deviceCode)
	resp.SetUserCode(userCode)
	resp.SetVerificationURI(d.VerificationURI)
	resp.SetVerificationURIComplete(d.VerificationURI + "?user_code=" + userCode)
	resp.SetExpiresIn(int64(time.Until(dar.GetSession().GetExpiresAt(fosite.UserCode)).Seconds()))
	resp.SetInterval(int(d.DeviceCodeRetryInterval.Seconds()))
	return nil
}
