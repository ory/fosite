package oauth2

import (
	"github.com/ory/fosite"
)

type audienceMatchingStrategy func(requested, allowed fosite.Arguments) error
