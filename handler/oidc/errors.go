package oidc

import "github.com/pkg/errors"

var (
	ErrInvalidSession = errors.New("Session type mismatch")
)
