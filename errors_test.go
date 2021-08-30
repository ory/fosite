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
	"fmt"
	"testing"

	"github.com/ory/fosite/i18n"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

func TestRFC6749Error(t *testing.T) {
	t.Run("case=wrap", func(t *testing.T) {
		orig := errors.New("hi")
		wrap := new(RFC6749Error)
		wrap.Wrap(orig)

		assert.EqualValues(t, orig.(stackTracer).StackTrace(), wrap.StackTrace())
	})

	t.Run("case=wrap_self", func(t *testing.T) {
		wrap := new(RFC6749Error)
		wrap.Wrap(wrap)

		assert.Empty(t, wrap.StackTrace())
	})
}

func TestRFC6749ErrorWithLocalizer(t *testing.T) {
	catalog := i18n.NewDefaultMessageCatalog([]*i18n.DefaultLocaleBundle{
		{
			LangTag: "en",
			Messages: []*i18n.DefaultMessage{
				{
					ID:               fmt.Sprintf("%s", i18n.ErrHintInvalidHTTPMethod),
					FormattedMessage: "HTTP method is '%s', expected 'POST'.",
				},
				{
					ID:               fmt.Sprintf("%s", i18n.ErrHintMalformedRequestBody),
					FormattedMessage: "Unable to parse HTTP body, make sure to send a properly formatted form request body.",
				},
			},
		},
		{
			LangTag: "es",
			Messages: []*i18n.DefaultMessage{
				{
					ID:               fmt.Sprintf("%s", i18n.ErrHintInvalidHTTPMethod),
					FormattedMessage: "El método HTTP es '%s', esperado 'POST'.",
				},
				{
					ID:               fmt.Sprintf("%s", i18n.ErrHintMalformedRequestBody),
					FormattedMessage: "No se puede analizar el cuerpo HTTP, asegúrese de enviar un cuerpo de solicitud de formulario con el formato adecuado.",
				},
				{
					ID:               "invalid_request",
					FormattedMessage: "A la solicitud le falta un parámetro obligatorio, incluye un valor de parámetro no válido, incluye un parámetro más de una vez o tiene un formato incorrecto.",
				},
			},
		},
	})

	err := ErrInvalidRequest.WithLocalizer(catalog, language.Spanish).
		WithHintID(i18n.ErrHintInvalidHTTPMethod, "GET")
	assert.Equal(t, "A la solicitud le falta un parámetro obligatorio, incluye un valor de parámetro no válido, incluye un parámetro más de una vez o tiene un formato incorrecto. El método HTTP es 'GET', esperado 'POST'.", err.GetDescription())
}
