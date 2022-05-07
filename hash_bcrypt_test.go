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

package fosite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestCompare(t *testing.T) {
	workfactor := 10
	hasher := &BCrypt{Config: &Config{HashCost: workfactor}}

	expectedPassword := "hello world"
	expectedPasswordHash, err := hasher.Hash(context.TODO(), []byte(expectedPassword))
	assert.NoError(t, err)
	assert.NotNil(t, expectedPasswordHash)

	testCases := []struct {
		testDescription  string
		providedPassword string
		shouldError      bool
	}{
		{
			testDescription:  "should not return an error if hash of provided password matches hash of expected password",
			providedPassword: expectedPassword,
			shouldError:      false,
		},
		{
			testDescription:  "should return an error if hash of provided password does not match hash of expected password",
			providedPassword: "some invalid password",
			shouldError:      true,
		},
	}

	for _, test := range testCases {
		t.Run(test.testDescription, func(t *testing.T) {
			hash, err := hasher.Hash(context.TODO(), []byte(test.providedPassword))
			assert.NoError(t, err)
			assert.NotNil(t, hash)

			err = hasher.Compare(context.TODO(), expectedPasswordHash, []byte(test.providedPassword))
			if test.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHash(t *testing.T) {
	validWorkFactor := 10
	invalidWorkFactor := 1000 // this is an invalid work factor that will cause the call to Hash to fail!
	password := []byte("bar")

	testCases := []struct {
		testDescription string
		workFactor      int
		shouldError     bool
	}{
		{
			testDescription: "should succeed if work factor is valid",
			workFactor:      validWorkFactor,
			shouldError:     false,
		},
		{
			testDescription: "should fail with error if work factor is invalid",
			workFactor:      invalidWorkFactor,
			shouldError:     true,
		},
	}

	for _, test := range testCases {
		t.Run(test.testDescription, func(t *testing.T) {
			hasher := &BCrypt{Config: &Config{HashCost: test.workFactor}}
			_, err := hasher.Hash(context.TODO(), password)
			if test.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultWorkFactor(t *testing.T) {
	b := &BCrypt{Config: &Config{}}
	data := []byte("secrets")
	hash, err := b.Hash(context.TODO(), data)
	if err != nil {
		t.Fatal(err)
	}

	cost, err := bcrypt.Cost(hash)
	if cost != 12 {
		t.Errorf("got cost factor %d", cost)
	}
}
