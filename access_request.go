package fosite

import "time"

type AccessRequest struct {
	GrantTypes       Arguments
	HandledGrantType Arguments
	RequestedAt      time.Time

	Request
}

func NewAccessRequest(session interface{}) *AccessRequest {
	r := &AccessRequest{
		GrantTypes :      Arguments{},
		HandledGrantType: Arguments{},
		Request: *NewRequest(),
	}
	r.Session = session
	return r
}

func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}
