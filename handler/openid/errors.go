// Copyright © 2022 Ory Corp

package openid

import "github.com/pkg/errors"

var (
	ErrInvalidSession = errors.New("Session type mismatch")
)
