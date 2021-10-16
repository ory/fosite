package fosite

import "net/http"

type PushedAuthorizeResponse struct {
	RequestURI string `json:"request_uri"`
	Header     http.Header
	Extra      map[string]interface{}
}

func NewPushedAuthorizeResponse() *PushedAuthorizeResponse {
	return &PushedAuthorizeResponse{
		Extra: map[string]interface{}{},
	}
}

func (a *PushedAuthorizeResponse) GetRequestURI() string {
	return a.RequestURI
}

func (a *PushedAuthorizeResponse) SetRequestURI(requestURI string) {
	a.RequestURI = requestURI
}

func (a *PushedAuthorizeResponse) GetHeader() http.Header {
	return a.Header
}

func (a *PushedAuthorizeResponse) AddHeader(key, value string) {
	a.Header.Add(key, value)
}

func (a *PushedAuthorizeResponse) SetExtra(key string, value interface{}) {
	a.Extra[key] = value
}

func (a *PushedAuthorizeResponse) GetExtra(key string) interface{} {
	return a.Extra[key]
}

func (a *PushedAuthorizeResponse) ToMap() map[string]interface{} {
	a.Extra["request_uri"] = a.RequestURI
	return a.Extra
}
