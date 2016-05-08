package oidc

import "github.com/go-errors/errors"

var (
	ErrInvalidSession = errors.New("Session type mismatch")
)
