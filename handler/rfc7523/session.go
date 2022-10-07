// Copyright © 2022 Ory Corp

package rfc7523

// Session must be implemented by the session if RFC7523 is to be supported.
type Session interface {
	// SetSubject sets the session's subject.
	SetSubject(subject string)
}
