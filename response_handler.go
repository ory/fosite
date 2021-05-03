package fosite

import "net/http"

type ResponseModeHandler interface {
	ResponseModes() ResponseModeTypes
	WriteAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder)
	WriteAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error)
}

type ResponseModeTypes []ResponseModeType

func (rs ResponseModeTypes) Has(item ResponseModeType) bool {
	for _, r := range rs {
		if r == item {
			return true
		}
	}
	return false
}

type DefaultResponseModeHandler struct{}

func (d *DefaultResponseModeHandler) ResponseModes() ResponseModeTypes { return nil }
func (d *DefaultResponseModeHandler) WriteAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder) {
}
func (d *DefaultResponseModeHandler) WriteAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error) {
}
