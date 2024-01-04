// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
)

func (f *Fosite) NewDeviceUserResponse(ctx context.Context, dur DeviceUserRequester, session Session) (DeviceUserResponder, error) {
	var resp = &DeviceUserResponse{}

	dur.SetSession(session)
	for _, h := range f.Config.GetDeviceUserEndpointHandlers(ctx) {
		if err := h.HandleDeviceUserEndpointRequest(ctx, dur, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
