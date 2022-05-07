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

	"github.com/ory/x/errorsx"

	"golang.org/x/crypto/bcrypt"
)

const DefaultBCryptWorkFactor = 12

// BCrypt implements the Hasher interface by using BCrypt.
type BCrypt struct {
	Config interface {
		BCryptCostProvider
	}
}

func (b *BCrypt) Hash(ctx context.Context, data []byte) ([]byte, error) {
	wf := b.Config.GetBCryptCost(ctx)
	if wf == 0 {
		wf = DefaultBCryptWorkFactor
	}
	s, err := bcrypt.GenerateFromPassword(data, wf)
	if err != nil {
		return nil, errorsx.WithStack(err)
	}
	return s, nil
}

func (b *BCrypt) Compare(ctx context.Context, hash, data []byte) error {
	if err := bcrypt.CompareHashAndPassword(hash, data); err != nil {
		return errorsx.WithStack(err)
	}
	return nil
}
