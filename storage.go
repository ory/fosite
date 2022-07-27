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

import "context"

// Storage defines fosite's minimal storage interface.
type Storage interface {
	ClientManager
}

// PARStorage holds information needed to store and retrieve PAR context.
type PARStorage interface {
	// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
	CreatePARSession(ctx context.Context, requestURI string, request AuthorizeRequester) error
	// GetPARSession gets the push authorization request context. The caller is expected to merge the AuthorizeRequest.
	GetPARSession(ctx context.Context, requestURI string) (AuthorizeRequester, error)
	// DeletePARSession deletes the context.
	DeletePARSession(ctx context.Context, requestURI string) (err error)
}
