// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
)

func (f *Fosite) NewDeviceAuthorizeResponse(ctx context.Context, dar DeviceAuthorizeRequester, session Session) (DeviceAuthorizeResponder, error) {
	var resp = &DeviceAuthorizeResponse{}

	dar.SetSession(session)
	for _, h := range f.Config.GetDeviceAuthorizeEndpointHandlers(ctx) {
		if err := h.HandleDeviceAuthorizeEndpointRequest(ctx, dar, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
