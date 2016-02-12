package fosite

import (
	"net/http"

	"github.com/ory-am/common/pkg"
)

func (c *Fosite) WriteAccessResponse(rw http.ResponseWriter, requester AccessRequester, responder AccessResponder) {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	pkg.WriteJSON(rw, responder.ToMap())
}
