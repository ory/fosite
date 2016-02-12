package fosite

import "time"

type AccessRequest struct {
	GrantTypes       Arguments
	HandledGrantType Arguments
	RequestedAt      time.Time

	Request
}

func NewAccessRequest(session interface{}) *AccessRequest {
	return &AccessRequest{
		Request: Request{
			Scopes:      Arguments{},
			Session:     session,
			RequestedAt: time.Now(),
		},
	}
}

func (a *AccessRequest) DidHandleGrantTypes() bool {
	for _, grantType := range a.GrantTypes {
		if !StringInSlice(grantType, a.HandledGrantType) {
			return false
		}
	}
	return true
}

func (a *AccessRequest) SetGrantTypeHandled(name string) {
	a.HandledGrantType = append(a.HandledGrantType, name)
}

func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}
