package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

// DeviceAuthorizationHandler is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
type DeviceHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	DeviceCodeStrategy     DeviceCodeStrategy
	UserCodeStrategy       UserCodeStrategy
	CoreStorage            CoreStorage
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		fosite.DeviceProvider
		fosite.DeviceAndUserCodeLifespanProvider
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.RefreshTokenScopesProvider
		fosite.SanitationAllowedProvider
	}
}

func (d *DeviceHandler) HandleDeviceEndpointRequest(ctx context.Context, dar fosite.Requester, resp fosite.DeviceResponder) error {
	deviceCode, deviceCodeSignature, err := d.DeviceCodeStrategy.GenerateDeviceCode(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	userCode, userCodeSignature, err := d.UserCodeStrategy.GenerateUserCode(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Save the real request_id
	requestId := dar.GetID()

	// Store the User Code session (this has no real data other that the uer and device code), can be converted into a 'full' session after user auth
	dar.GetSession().SetExpiresAt(fosite.AuthorizeCode, time.Now().UTC().Add(d.Config.GetDeviceAndUserCodeLifespan(ctx)))
	if err := d.CoreStorage.CreateDeviceCodeSession(ctx, deviceCodeSignature, dar.Sanitize(nil)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Fake the RequestId field to store the DeviceCodeSignature for easy handling
	dar.SetID(deviceCodeSignature)
	dar.GetSession().SetExpiresAt(fosite.UserCode, time.Now().UTC().Add(d.Config.GetDeviceAndUserCodeLifespan(ctx)).Round(time.Second))
	if err := d.CoreStorage.CreateUserCodeSession(ctx, userCodeSignature, dar.Sanitize(nil)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	dar.SetID(requestId)

	// Populate the response fields
	resp.SetDeviceCode(deviceCode)
	resp.SetUserCode(userCode)
	resp.SetVerificationURI(d.Config.GetDeviceVerificationURL(ctx))
	resp.SetVerificationURIComplete(d.Config.GetDeviceVerificationURL(ctx) + "?user_code=" + userCode)
	resp.SetExpiresIn(int64(time.Until(dar.GetSession().GetExpiresAt(fosite.UserCode)).Seconds()))
	resp.SetInterval(int(d.Config.GetDeviceAuthTokenPollingInterval(ctx).Seconds()))
	return nil
}
