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

func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}
