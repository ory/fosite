/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/ory/fosite"
)

func TestRequest(t *testing.T) {
	r := &Request{
		RequestedAt:       time.Now().UTC(),
		Client:            &DefaultClient{},
		RequestedScope:    Arguments{"scope"},
		GrantedScope:      Arguments{"scope"},
		RequestedAudience: Arguments{"scope"},
		GrantedAudience:   Arguments{"scope"},
		Form:              url.Values{"foo": []string{"bar"}},
		Session:           new(DefaultSession),
	}

	assert.Equal(t, r.RequestedAt, r.GetRequestedAt())
	assert.Equal(t, r.Client, r.GetClient())
	assert.Equal(t, r.GrantedScope, r.GetGrantedScopes())
	assert.Equal(t, r.RequestedScope, r.GetRequestedScopes())
	assert.Equal(t, r.Form, r.GetRequestForm())
	assert.Equal(t, r.Session, r.GetSession())
}

func TestMergeRequest(t *testing.T) {
	a := &Request{
		ID:                "123",
		RequestedAt:       time.Now().UTC(),
		Client:            &DefaultClient{ID: "123"},
		RequestedScope:    Arguments{"scope-3", "scope-4"},
		RequestedAudience: Arguments{"aud-3", "aud-4"},
		GrantedScope:      []string{"scope-1", "scope-2"},
		GrantedAudience:   []string{"aud-1", "aud-2"},
		Form:              url.Values{"foo": []string{"fasdf"}},
		Session:           new(DefaultSession),
	}
	b := &Request{
		RequestedAt:    time.Now().UTC(),
		Client:         &DefaultClient{},
		RequestedScope: Arguments{},
		GrantedScope:   []string{},
		Form:           url.Values{},
		Session:        new(DefaultSession),
	}

	b.Merge(a)
	assert.EqualValues(t, a.RequestedAt, b.RequestedAt)
	assert.EqualValues(t, a.Client, b.Client)
	assert.EqualValues(t, a.RequestedScope, b.RequestedScope)
	assert.EqualValues(t, a.RequestedAudience, b.RequestedAudience)
	assert.EqualValues(t, a.GrantedScope, b.GrantedScope)
	assert.EqualValues(t, a.GrantedAudience, b.GrantedAudience)
	assert.EqualValues(t, a.Form, b.Form)
	assert.EqualValues(t, a.Session, b.Session)
	assert.EqualValues(t, a.ID, b.ID)
}

func TestSanitizeRequest(t *testing.T) {
	a := &Request{
		RequestedAt:    time.Now().UTC(),
		Client:         &DefaultClient{ID: "123"},
		RequestedScope: Arguments{"asdff"},
		GrantedScope:   []string{"asdf"},
		Form: url.Values{
			"foo": []string{"fasdf"},
			"bar": []string{"fasdf", "faaaa"},
			"baz": []string{"fasdf"},
		},
		Session: new(DefaultSession),
	}

	b := a.Sanitize([]string{"bar", "baz"})
	assert.NotEqual(t, a.Form.Encode(), b.GetRequestForm().Encode())

	assert.Empty(t, b.GetRequestForm().Get("foo"))
	assert.Equal(t, "fasdf", b.GetRequestForm().Get("bar"))
	assert.Equal(t, []string{"fasdf", "faaaa"}, b.GetRequestForm()["bar"])
	assert.Equal(t, "fasdf", b.GetRequestForm().Get("baz"))

	assert.Equal(t, "fasdf", a.GetRequestForm().Get("foo"))
	assert.Equal(t, "fasdf", a.GetRequestForm().Get("bar"))
	assert.Equal(t, []string{"fasdf", "faaaa"}, a.GetRequestForm()["bar"])
	assert.Equal(t, "fasdf", a.GetRequestForm().Get("baz"))
}

func TestIdentifyRequest(t *testing.T) {
	a := &Request{
		RequestedAt:    time.Now().UTC(),
		Client:         &DefaultClient{},
		RequestedScope: Arguments{},
		GrantedScope:   []string{},
		Form:           url.Values{"foo": []string{"bar"}},
		Session:        new(DefaultSession),
	}

	b := a.Sanitize([]string{})
	b.GetID()
	assert.Equal(t, a.ID, b.GetID())
}
