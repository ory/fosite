package fosite

import (
	"github.com/ory-am/fosite/client"
	"time"
)

type AccessRequest struct {
	GrantType        string
	HandledGrantType []string
	RequestedAt      time.Time
	Client           client.Client
	Scopes           Arguments
	GrantedScopes    []string
	Session          interface{}

	Request
}

func (a *AccessRequest) DidHandleGrantType() bool {
	return StringInSlice(a.GrantType, a.HandledGrantType)
}

func (a *AccessRequest) SetGrantTypeHandled(name string) {
	a.HandledGrantType = append(a.HandledGrantType, name)
}

func (a *AccessRequest) GetGrantType() string {
	return a.GrantType
}
