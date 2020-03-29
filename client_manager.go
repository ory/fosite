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
	"time"
)

// ClientManager defines the (persistent) manager interface for clients.
type ClientManager interface {
	// GetClient loads the client by its ID or returns an error
	// if the client does not exist or another error occurred.
	GetClient(ctx context.Context, id string) (Client, error)
	// ClientAssertionJWTValid returns an error if the JTI is
	// known or the DB check failed and nil if the JTI is not known.
	ClientAssertionJWTValid(ctx context.Context, jti string) error
	// SetClientAssertionJWT marks a JTI as known for the given
	// expiry time. Before inserting the new JTI, it will clean
	// up any existing JTIs that have expired as those tokens can
	// not be replayed due to the expiry.
	SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error
}
