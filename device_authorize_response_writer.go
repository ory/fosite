package fosite

import (
	"context"
	"fmt"
)

func (f *Fosite) NewDeviceAuthorizeResponse(ctx context.Context, r Requester) (DeviceAuthorizeResponder, error) {
	var resp = NewDeviceAuthorizeResponse()

	for _, h := range f.Config.GetDeviceAuthorizeEndpointHandlers(ctx) {
		fmt.Println("NewDeviceAuthorizeResponse +++")
		if err := h.HandleDeviceAuthorizeEndpointRequest(ctx, r, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
