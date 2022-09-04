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
	deviceStore := storage.NewMemoryStore()
	userStore := storage.NewMemoryStore()
	handler := DeviceAuthorizationHandler{
		DeviceCodeStorage:  deviceStore,
		UserCodeStorage:    userStore,
		DeviceCodeStrategy: hmacshaStrategy,
		UserCodeStrategy:   hmacshaStrategy,
		Config: &fosite.Config{
			DeviceAndUserCodeLifespan:      time.Minute * 10,
			DeviceAuthTokenPollingInterval: time.Second * 10,
			DeviceVerificationURL:          "www.test.com",
			AccessTokenLifespan:            time.Hour,
			RefreshTokenLifespan:           time.Hour,
			ScopeStrategy:                  fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
			RefreshTokenScopes:             []string{"offline"},
		},
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
