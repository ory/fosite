package fosite

import (
	"time"
)

type AccessRequest struct {
	GrantType        string
	HandledGrantType []string
	RequestedAt      time.Time

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
