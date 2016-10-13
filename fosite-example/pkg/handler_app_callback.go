package pkg

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/oauth2"
)

func CallbackHandler(c oauth2.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(`<h1>Callback site</h1><a href="/">Go back</a>`))
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		if req.URL.Query().Get("error") != "" {
			rw.Write([]byte(fmt.Sprintf(`<h1>Error!</h1>
			Error: %s<br>
			Description: %s<br>
			<br>`,
				req.URL.Query().Get("error"),
				req.URL.Query().Get("error_description"),
			)))
			return
		}

		if req.URL.Query().Get("revoke") != "" {
			revokeURL := strings.Replace(c.Endpoint.TokenURL, "token", "revoke", 1)
			resp, body, errs := gorequest.New().Post(revokeURL).SetBasicAuth(c.ClientID, c.ClientSecret).SendString(url.Values{
				"token_type_hint": {"refresh_token"},
				"token":           {req.URL.Query().Get("revoke")},
			}.Encode()).End()
			if len(errs) > 0 {
				rw.Write([]byte(fmt.Sprintf(`<p>Could not revoke token %s</p>`, errs)))
				return
			}

			rw.Write([]byte(fmt.Sprintf(`<p>Received status code from the revoke endpoint:<br><code>%d</code></p>`, resp.StatusCode)))
			if body != "" {
				rw.Write([]byte(fmt.Sprintf(`<p>Got a response from the revoke endpoint:<br><code>%s</code></p>`, body)))
			}

			rw.Write([]byte(fmt.Sprintf(`<p>These tokens have been revoked, try to use the refresh token by <br><a href="%s">by clicking here</a></p>`, "?refresh="+url.QueryEscape(req.URL.Query().Get("revoke")))))
			rw.Write([]byte(fmt.Sprintf(`<p>Try to use the access token by <br><a href="%s">by clicking here</a></p>`, "/protected-api?token="+url.QueryEscape(req.URL.Query().Get("access_token")))))

			return
		}

		if req.URL.Query().Get("refresh") != "" {
			_, body, errs := gorequest.New().Post(c.Endpoint.TokenURL).SetBasicAuth(c.ClientID, c.ClientSecret).SendString(url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {req.URL.Query().Get("refresh")},
				"scope":         {"fosite"},
			}.Encode()).End()
			if len(errs) > 0 {
				rw.Write([]byte(fmt.Sprintf(`<p>Could not refresh token %s</p>`, errs)))
				return
			}
			rw.Write([]byte(fmt.Sprintf(`<p>Got a response from the refresh grant:<br><code>%s</code></p>`, body)))
			return
		}

		if req.URL.Query().Get("code") == "" {
			rw.Write([]byte(fmt.Sprintln(`<p>Could not find the authorize code. If you've used the implicit grant, check the
			browser location bar for the
			access token <small><a href="http://en.wikipedia.org/wiki/Fragment_identifier#Basics">(the server side does not have access to url fragments)</a></small>
			</p>`,
			)))
			return
		}

		rw.Write([]byte(fmt.Sprintf(`<p>Amazing! You just got an authorize code!:<br><code>%s</code></p>
		<p>Click <a href="/">here to return</a> to the front page</p>`,
			req.URL.Query().Get("code"),
		)))

		token, err := c.Exchange(oauth2.NoContext, req.URL.Query().Get("code"))
		if err != nil {
			rw.Write([]byte(fmt.Sprintf(`<p>I tried to exchange the authorize code for an access token but it did not work but got error: %s</p>`, err.Error())))
			return
		}

		rw.Write([]byte(fmt.Sprintf(`<p>Cool! You are now a proud token owner.<br>
		<ul>
			<li>
				Access token (click to make <a href="%s">authorized call</a>):<br>
				<code>%s</code>
			</li>
			<li>
				Refresh token (click <a href="%s">here to use it</a>) (click <a href="%s">here to revoke it</a>):<br>
				<code>%s</code>
			</li>
			<li>
				Extra info: <br>
				<code>%s</code>
			</li>
		</ul>`,
			"/protected-api?token="+token.AccessToken,
			token.AccessToken,
			"?refresh="+url.QueryEscape(token.RefreshToken),
			"?revoke="+url.QueryEscape(token.RefreshToken)+"&access_token="+url.QueryEscape(token.AccessToken),
			token.RefreshToken,
			token,
		)))
	}
}
