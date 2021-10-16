package fosite

type PushedAuthorizeResponse struct {
	RequestURI string `json:"request_uri"`
}

func (a *PushedAuthorizeResponse) GetRequestURI() string {
	return a.RequestURI
}

func (a *PushedAuthorizeResponse) SetRequestURI(requestURI string) {
	a.RequestURI = requestURI
}
