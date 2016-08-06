package pkg

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

func HomeHandler(c oauth2.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(fmt.Sprintf(`
		<p>You can obtain an access token using various methods</p>
		<ul>
			<li>
				<a href="%s">Authorize code grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="%s">Implicit grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="/client">Client credentials grant</a>
			</li>
			<li>
				<a href="/owner">Resource owner password credentials grant</a>
			</li>
			<li>
				<a href="%s">Refresh grant</a>. <small>You will first see the login screen which is required to obtain a valid refresh token.</small>
			</li>
			<li>
				<a href="%s">Make an invalid request</a>
			</li>
		</ul>`,
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"http://localhost:3846/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3846%2Fcallback&response_type=token%20id_token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce",
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"/auth?client_id=my-client&scope=fosite&response_type=123&redirect_uri=http://localhost:3846/callback",
		)))
	}
}
