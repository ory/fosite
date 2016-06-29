package integration_test

import (
	"net/http"
	"testing"

	hst "github.com/ory-am/fosite/handler/core/strategy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasic(t *testing.T) {
	f := newFosite()
	ts := mockServer(t, f, &mySessionData{
		HMACSession: new(hst.HMACSession),
	})
	defer ts.Close()

	client := newOAuth2Client(ts)
	resp, err := http.Get(client.AuthCodeURL(""))
	defer resp.Body.Close()
	require.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
