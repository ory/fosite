package fosite

import (
	"github.com/ory-am/common/pkg"
	"net/http"
)

func (c *Fosite) WriteAccessResponse(rw http.ResponseWriter, requester AccessRequester, responder AccessResponder) {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	pkg.WriteJSON(rw, responder.ToMap())
}
