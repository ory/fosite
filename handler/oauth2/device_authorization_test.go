package oauth2

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
)

func Test_HandleDeviceAuthorizeEndpointRequest(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	store := storage.NewMemoryStore()
	handler := DeviceAuthorizationHandler{
		DeviceCodeStorage:  store,
		DeviceCodeStrategy: hmacshaStrategy,
		UserCodeStrategy:   hmacshaStrategy,
		DeviceCodeLifespan: time.Minute * 5,
		UserCodeLifespan:   time.Minute * 5,
		VerificationURI:    "www.test.com",
	}

	req := &fosite.AuthorizeRequest{
		ResponseTypes: fosite.Arguments{"code"},
		Request: fosite.Request{
			Session: &fosite.DefaultSession{},
		},
	}
	resp := fosite.NewDeviceAuthorizeResponse()

	handler.HandleDeviceAuthorizeEndpointRequest(nil, req, resp)

	assert.NotEmpty(t, resp.GetDeviceCode())
	assert.NotEmpty(t, resp.GetUserCode())
	assert.Equal(t, len(resp.GetUserCode()), 8)
	assert.Equal(t, len(resp.GetDeviceCode()), 100)
	assert.Equal(t, resp.GetVerificationURI(), "www.test.com")

}
