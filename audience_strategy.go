package fosite

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/ory/go-convenience/stringsx"
)

type AudienceMatchingStrategy func(haystack []string, needle []string) error

func DefaultAudienceMatchingStrategy(haystack []string, needle []string) error {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		nu, err := url.Parse(n)
		if err != nil {
			return errors.WithStack(ErrInvalidRequest.WithHintf(`Unable to parse requested audience "%s".`, n).WithDebug(err.Error()))
		}

		var found bool
		for _, h := range haystack {
			hu, err := url.Parse(h)
			if err != nil {
				return errors.WithStack(ErrInvalidRequest.WithHintf(`Unable to parse whitelisted audience "%s".`, h).WithDebug(err.Error()))
			}

			allowedPath := strings.TrimRight(hu.Path, "/")
			if nu.Scheme == hu.Scheme &&
				nu.Host == hu.Host &&
				(nu.Path == hu.Path ||
					nu.Path == allowedPath ||
					len(nu.Path) > len(allowedPath) && strings.TrimRight(nu.Path[:len(allowedPath)+1], "/")+"/" == allowedPath+"/") {
				found = true
			}
		}

		if !found {
			return errors.WithStack(ErrInvalidRequest.WithHintf(`Requested audience "%s" has not been whitelisted by the OAuth 2.0 Client.`, n))
		}
	}

	return nil
}

func (f *Fosite) validateAuthorizeAudience(r *http.Request, request *AuthorizeRequest) error {
	audience := stringsx.Splitx(request.Form.Get("audience"), " ")

	if err := f.AudienceMatchingStrategy(request.Client.GetAudience(), audience); err != nil {
		return err
	}

	request.SetRequestedAudience(Arguments(audience))
	return nil
}
