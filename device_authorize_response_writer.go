package fosite

import (
	"context"
)

func (f *Fosite) NewDeviceAuthorizeResponse(ctx context.Context, r Requester) (DeviceAuthorizeResponder, error) {
	var resp = NewDeviceAuthorizeResponse()

	for _, h := range f.DeviceAuthorizeEndpointHandlers {
		if err := h.HandleDeviceAuthorizeEndpointRequest(ctx, r, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
