package rfc8693

// Session is required to support token exchange
type Session interface {
	// SetSubject sets the session's subject.
	SetSubject(subject string)

	SetActorToken(token map[string]interface{})

	GetActorToken() map[string]interface{}

	SetSubjectToken(token map[string]interface{})

	GetSubjectToken() map[string]interface{}

	SetAct(act map[string]interface{})

	AccessTokenClaimsMap() map[string]interface{}
}
