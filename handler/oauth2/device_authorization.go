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
	DeviceCodeStorage DeviceCodeStorage
	UserCodeStorage   UserCodeStorage

	CoreStorage CoreStorage

	DeviceCodeStrategy DeviceCodeStrategy
	UserCodeStrategy   UserCodeStrategy

	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	TokenRevocationStorage TokenRevocationStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan defines the lifetime of a refresh token.
	RefreshTokenLifespan time.Duration

	// DeviceCodeLifespan defines the lifetime of the device code
	DeviceCodeLifespan time.Duration

	// UserCodeLifespan defines the lifetime of the user code
	UserCodeLifespan time.Duration

	// PollingInterval defines the minimum amount of time in seconds that the client SHOULD wait between polling requests to the token endpoint.
	PollingInterval time.Duration

	VerificationURI string

	RefreshTokenScopes []string
}

func (d *DeviceAuthorizationHandler) HandleDeviceAuthorizeEndpointRequest(ctx context.Context, dar fosite.DeviceAuthorizeRequester, resp fosite.DeviceAuthorizeResponder) error {
	deviceCode, deviceCodeSignature, err := d.DeviceCodeStrategy.GenerateDeviceCode(ctx, dar)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	userCode, userCodeSignature, err := d.UserCodeStrategy.GenerateUserCode(ctx, dar)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Set Device Code expiry time
	dar.GetSession().SetExpiresAt(fosite.DeviceCode, time.Now().UTC().Add(d.DeviceCodeLifespan).Round(time.Second))

	// Store the Device Code
	if err := d.DeviceCodeStorage.CreateDeviceCodeSession(ctx, deviceCodeSignature, dar.Sanitize(nil)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Set User Code expiry time
	dar.GetSession().SetExpiresAt(fosite.UserCode, time.Now().UTC().Add(d.UserCodeLifespan).Round(time.Second))

	// Store the User Code
	if err := d.UserCodeStorage.CreateUserCodeSession(ctx, userCodeSignature, dar.Sanitize(nil)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Populate the response fields
	resp.SetDeviceCode(deviceCode)
	resp.SetUserCode(userCode)
	resp.SetVerificationURI(d.VerificationURI)
	resp.SetVerificationURIComplete(d.VerificationURI + "?user_code=" + userCode)
	resp.SetExpiresIn(int64(time.Until(dar.GetSession().GetExpiresAt(fosite.UserCode)).Seconds()))
	resp.SetInterval(int(d.PollingInterval.Seconds()))

	return nil
}

func (d *DeviceAuthorizationHandler) AuthorizeDeviceCode(ctx context.Context, deviceCode string, requester fosite.Requester) error {
	signature := d.DeviceCodeStrategy.DeviceCodeSignature(deviceCode)
	return d.DeviceCodeStorage.UpdateDeviceCodeSession(ctx, signature, requester)
}