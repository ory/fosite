// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ory/x/errorsx"
)

type RFC9396AuthorizationDetailsType struct {
	// Type is the authorization details type that is a mandatory part of the
	// authorization details object prescribed by RFC9396.
	Type string `json:"type,omitempty"`

	// Locations is an array of strings representing the location of the resource or RS.
	// These strings are typically URIs identifying the location of the RS.
	Locations []string `json:"locations,omitempty"`

	// Actions is an array of strings representing the kinds of actions to be taken at the resource.
	Actions []string `json:"actions,omitempty"`

	// Datatypes is an array of strings representing the kinds of data being requested from the resource.
	Datatypes []string `json:"datatypes,omitempty"`

	// Identifier is a string identifier indicating a specific resource available at the API.
	Identifier string `json:"identifier,omitempty"`

	// Privileges is an array of strings representing the types or levels of privilege being requested at the resource.
	Privileges []string `json:"privileges,omitempty"`

	// Extra contains data that is non-prescriptive.
	Extra map[string]interface{} `json:"-"`

	// RFC9396AuthorizationDetailsTypeHandler extends the object with custom equals and validate functions.
	RFC9396AuthorizationDetailsTypeHandler `json:"-"`
}

func (ad *RFC9396AuthorizationDetailsType) Equals(cmp *RFC9396AuthorizationDetailsType) bool {
	if ad == nil && cmp == nil {
		return true
	}

	if ad == nil || cmp == nil {
		return false
	}

	if adID, err := ad.RFC9396AuthorizationDetailsTypeHandler.GetID(ad); err != nil {
		return false
	} else if cmpID, err := cmp.RFC9396AuthorizationDetailsTypeHandler.GetID(cmp); err != nil {
		return false
	} else {
		return ad.Type == cmp.Type && adID == cmpID
	}
}

func (ad *RFC9396AuthorizationDetailsType) Validate() error {
	return ad.RFC9396AuthorizationDetailsTypeHandler.Validate(ad)
}

func (ad *RFC9396AuthorizationDetailsType) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	ad.Type, _ = m["type"].(string)
	ad.Actions = Map(m).SafeStringSlice("actions", nil)
	ad.Datatypes = Map(m).SafeStringSlice("datatypes", nil)
	ad.Identifier, _ = m["identifier"].(string)
	ad.Locations = Map(m).SafeStringSlice("locations", nil)
	ad.Privileges = Map(m).SafeStringSlice("privileges", nil)

	for k, v := range m {
		if k == "type" || k == "actions" || k == "datatypes" || k == "identifier" || k == "locations" || k == "privileges" {
			continue
		}

		if ad.Extra == nil {
			ad.Extra = map[string]interface{}{}
		}

		ad.Extra[k] = v
	}

	return nil
}

func (ad *RFC9396AuthorizationDetailsType) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"type":       ad.Type,
		"actions":    ad.Actions,
		"datatypes":  ad.Datatypes,
		"identifier": ad.Identifier,
		"locations":  ad.Locations,
		"privileges": ad.Privileges,
	}

	for k, v := range ad.Extra {
		m[k] = v
	}

	return json.Marshal(m)
}

func (ad *RFC9396AuthorizationDetailsType) DecorateWithTypeHandler(ctx context.Context, config RFC9396ConfigProvider) {
	typeHandlers := config.GetAuthorizationDetailTypeHandlers(ctx)
	if typeHandler, ok := typeHandlers[ad.Type]; ok {
		ad.RFC9396AuthorizationDetailsTypeHandler = typeHandler
	} else {
		ad.RFC9396AuthorizationDetailsTypeHandler = &RFC9396DefaultAuthorizationDetailsTypeHandler{}
	}
}

func (ad *RFC9396AuthorizationDetailsType) String() string {
	if ad == nil {
		return "<nil>"
	}

	return fmt.Sprintf("%+v", *ad)
}

type RFC9396AuthorizationDetailsTypeHandler interface {
	Validate(t *RFC9396AuthorizationDetailsType) error

	GetID(t *RFC9396AuthorizationDetailsType) (string, error)
}

type RFC9396DefaultAuthorizationDetailsTypeHandler struct {
	RFC9396GetAuthorizationDetailsIDStrategy
}

// Validate validates the common properties.
func (h *RFC9396DefaultAuthorizationDetailsTypeHandler) Validate(t *RFC9396AuthorizationDetailsType) error {
	if len(t.Type) == 0 {
		return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHint("Missing 'type' in the authorization details object."))
	}

	return nil
}

// GetID generates a unique identifier to identify this object
func (h *RFC9396DefaultAuthorizationDetailsTypeHandler) GetID(t *RFC9396AuthorizationDetailsType) (string, error) {
	if h.RFC9396GetAuthorizationDetailsIDStrategy == nil {
		h.RFC9396GetAuthorizationDetailsIDStrategy = RFC9396GetAuthorizationDetailsIDDefaultStrategy
	}
	return h.RFC9396GetAuthorizationDetailsIDStrategy(t)
}

type RFC9396GetAuthorizationDetailsIDStrategy func(t *RFC9396AuthorizationDetailsType) (string, error)

func RFC9396GetAuthorizationDetailsIDDefaultStrategy(t *RFC9396AuthorizationDetailsType) (string, error) {
	// sort the string array first to get consistent result
	sort.Strings(t.Actions)
	sort.Strings(t.Datatypes)
	sort.Strings(t.Locations)
	sort.Strings(t.Privileges)
	// key is concatenation of known fields, then hash it
	key := fmt.Sprintf("%v.%v.%v.%v.%v", t.Identifier, t.Actions, t.Datatypes, t.Locations, t.Privileges)
	hash := sha512.Sum512([]byte(key))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func RFC9396GetAuthorizationDetailsTypeIDJSONHashStrategy(t *RFC9396AuthorizationDetailsType) (string, error) {
	// for this, we just hash the whole json
	if b, err := t.MarshalJSON(); err == nil {
		hash := sha512.Sum512(b)
		return base64.RawURLEncoding.EncodeToString(hash[:]), nil
	} else {
		return "", err
	}
}

// RFC9396AuthorizationDetailsStrategy is a strategy for matching authorization detail types.
// This mirrors ScopeStrategy.
type RFC9396AuthorizationDetailsStrategy func(haystack []string, needle string) bool

func RFC9396ExactAuthorizationDetailsStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}

type RFC9396Client interface {
	// GetAuthorizationDetailTypes returns the list of authorization detail types supported
	// for the client.
	GetAuthorizationDetailTypes() Arguments
}

type DefaultRFC9396Client struct {
	*DefaultClient
	AuthorizationDetails Arguments
}

// GetAuthorizationDetailTypes returns the list of authorization detail types supported
// for the client.
func (c *DefaultRFC9396Client) GetAuthorizationDetailTypes() Arguments {
	return c.AuthorizationDetails
}
