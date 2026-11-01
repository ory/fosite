// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestJOSE4RejectsUnsafeEmbeddedKeysBeforeKeyfunc(t *testing.T) {
	large := make([]byte, 2049)
	large[0] = 128
	huge := base64.RawURLEncoding.EncodeToString(large)
	for _, header := range []string{
		`{"alg":"RS256","jwk":{"kty":"RSA","n":"AQ","e":"AQAB","d":"AQ","p":"` + huge + `","q":"Aw"}}`,
		`{"alg":"RS256","jwk":{"kty":"RSA","n":"` + huge + `","e":"AQAB"}}`,
	} {
		raw := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".e30.eA"
		called := false
		_, err := ParseWithClaims(raw, MapClaims{}, func(*Token) (interface{}, error) { called = true; return nil, nil })
		if err == nil || called {
			t.Fatalf("unsafe key parsed: err=%v keyfunc=%v", err, called)
		}
		if !strings.Contains(err.Error(), "private parameters") && !strings.Contains(err.Error(), "modulus too large") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	}
}

func TestJOSE4RejectsTypedNilVerificationKeysWithoutPanicking(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := NewWithClaims(jose.RS256, MapClaims{"sub": "typed-nil"}).SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	var nilBytes *[]byte
	var nilEd25519 *ed25519.PublicKey
	for name, key := range map[string]interface{}{
		"byte slice pointer":         nilBytes,
		"Ed25519 public key pointer": nilEd25519,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseWithClaims(raw, MapClaims{}, func(*Token) (interface{}, error) { return key, nil })
			if err == nil {
				t.Fatal("typed nil verification key unexpectedly accepted")
			}
		})
	}
}

func TestJOSE4PreservesSignedAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		alg          jose.SignatureAlgorithm
		sign, verify interface{}
	}{}
	for _, alg := range []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512} {
		cases = append(cases, struct {
			alg          jose.SignatureAlgorithm
			sign, verify interface{}
		}{alg, rsaKey, &rsaKey.PublicKey})
	}
	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
		key := []byte(strings.Repeat("test-only-key-", 8))
		cases = append(cases, struct {
			alg          jose.SignatureAlgorithm
			sign, verify interface{}
		}{alg, key, key})
	}
	for _, ec := range []struct {
		alg   jose.SignatureAlgorithm
		curve elliptic.Curve
	}{{jose.ES256, elliptic.P256()}, {jose.ES384, elliptic.P384()}, {jose.ES512, elliptic.P521()}} {
		key, err := ecdsa.GenerateKey(ec.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			alg          jose.SignatureAlgorithm
			sign, verify interface{}
		}{ec.alg, key, &key.PublicKey})
	}
	cases = append(cases, struct {
		alg          jose.SignatureAlgorithm
		sign, verify interface{}
	}{jose.EdDSA, edKey, edPub})
	for _, tc := range cases {
		t.Run(string(tc.alg), func(t *testing.T) {
			claims := MapClaims{"sub": "preserved", "exp": time.Now().Add(time.Minute).Unix()}
			raw, err := NewWithClaims(tc.alg, claims).SignedString(tc.sign)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseWithClaims(raw, MapClaims{}, func(token *Token) (interface{}, error) {
				if token.Method != tc.alg {
					t.Fatalf("algorithm changed: %s", token.Method)
				}
				return tc.verify, nil
			})
			if err != nil || !parsed.Valid() {
				t.Fatalf("valid %s failed: %v", tc.alg, err)
			}
			_, err = ParseWithClaims(raw, MapClaims{}, func(*Token) (interface{}, error) { return []byte("wrong-key"), nil })
			if err == nil {
				t.Fatal("wrong key accepted")
			}
		})
	}
}

func TestJOSE4RSAKeyRoundTrip(t *testing.T) {
	for _, bits := range []int{2048, 4096} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			private, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []interface{}{private, &private.PublicKey} {
				encoded, err := json.Marshal(jose.JSONWebKey{Key: key})
				if err != nil {
					t.Fatal(err)
				}
				var decoded jose.JSONWebKey
				if err := json.Unmarshal(encoded, &decoded); err != nil {
					t.Fatal(err)
				}
				if !decoded.Valid() || decoded.Public().Key.(*rsa.PublicKey).N.Cmp(private.N) != 0 {
					t.Fatal("RSA key changed")
				}
			}
		})
	}
}

func TestJOSE4UnsafeRSAHeadersCompactAndJSON(t *testing.T) {
	large := make([]byte, 2049)
	large[0] = 128
	huge := base64.RawURLEncoding.EncodeToString(large)
	for _, field := range []string{"n", "p", "q", "d"} {
		key := map[string]string{"kty": "RSA", "n": "Dw", "e": "AQAB"}
		expected := "modulus too large"
		if field != "n" {
			key["d"] = "Aw"
			key["p"] = "Aw"
			key["q"] = "BQ"
			expected = "private parameters"
		}
		key[field] = huge
		header, err := json.Marshal(map[string]interface{}{"alg": "RS256", "jwk": key})
		if err != nil {
			t.Fatal(err)
		}
		protected := base64.RawURLEncoding.EncodeToString(header)
		for format, raw := range map[string]string{"compact": protected + ".e30.eA", "flattened": `{"protected":"` + protected + `","payload":"e30","signature":"eA"}`, "general-unprotected": `{"payload":"e30","signatures":[{"header":` + string(header) + `,"signature":"eA"}]}`} {
			t.Run(field+"/"+format, func(t *testing.T) {
				_, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
				if err == nil || !strings.Contains(err.Error(), expected) {
					t.Fatalf("expected %s, got %v", expected, err)
				}
			})
		}
	}
}

func TestJOSE4PrivateHeaderErrorRedaction(t *testing.T) {
	const sentinel = "private-key-input-must-not-appear-in-errors"
	private := map[string]interface{}{"kty": "RSA", "n": "Dw", "e": "AQAB", "d": "Aw", "p": "Aw", "q": "BQ", "kid": sentinel}
	assertError := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("private key accepted")
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("private input leaked: %v", err)
		}
	}
	jwsHeader, _ := json.Marshal(map[string]interface{}{"alg": "RS256", "jwk": private})
	protected := base64.RawURLEncoding.EncodeToString(jwsHeader)
	for name, raw := range map[string]string{"compact": protected + ".e30.eA", "flattened": `{"protected":"` + protected + `","payload":"e30","signature":"eA"}`, "general": `{"payload":"e30","signatures":[{"header":` + string(jwsHeader) + `,"signature":"eA"}]}`} {
		t.Run("JWS-JWK/"+name, func(t *testing.T) {
			_, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
			assertError(t, err)
			if !strings.Contains(err.Error(), "private parameters") {
				t.Fatalf("unexpected boundary: %v", err)
			}
		})
	}
	jweHeader, _ := json.Marshal(map[string]interface{}{"alg": "dir", "enc": "A256GCM", "jwk": private})
	protected = base64.RawURLEncoding.EncodeToString(jweHeader)
	for name, raw := range map[string]string{"compact": protected + "..eA.eA.eA", "flattened": `{"protected":"` + protected + `","iv":"eA","ciphertext":"eA","tag":"eA"}`, "general": `{"protected":"` + protected + `","recipients":[{}],"iv":"eA","ciphertext":"eA","tag":"eA"}`} {
		t.Run("JWE-JWK/"+name, func(t *testing.T) {
			_, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
			assertError(t, err)
			if !strings.Contains(err.Error(), "private parameters") {
				t.Fatalf("unexpected boundary: %v", err)
			}
		})
	}
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: &recipient.PublicKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encrypter.Encrypt([]byte("valid-public-epk"))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jose.ParseEncrypted(compact, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := parsed.Decrypt(recipient)
	if err != nil || string(plaintext) != "valid-public-epk" {
		t.Fatalf("valid EPK failed: %v", err)
	}
	parts := strings.Split(compact, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		t.Fatal(err)
	}
	epk := header["epk"].(map[string]interface{})
	epk["d"] = base64.RawURLEncoding.EncodeToString([]byte(sentinel))
	epk["kid"] = sentinel
	changed, _ := json.Marshal(header)
	parts[0] = base64.RawURLEncoding.EncodeToString(changed)
	for name, raw := range map[string]string{"compact": strings.Join(parts, "."), "flattened": `{"protected":"` + parts[0] + `","iv":"` + parts[2] + `","ciphertext":"` + parts[3] + `","tag":"` + parts[4] + `"}`, "general": `{"protected":"` + parts[0] + `","recipients":[{}],"iv":"` + parts[2] + `","ciphertext":"` + parts[3] + `","tag":"` + parts[4] + `"}`} {
		t.Run("JWE-EPK/"+name, func(t *testing.T) {
			parsed, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				t.Fatalf("EPK header did not reach decryption boundary: %v", err)
			}
			plaintext, err := parsed.Decrypt(recipient)
			assertError(t, err)
			if err != jose.ErrCryptoFailure || len(plaintext) != 0 {
				t.Fatalf("unexpected private EPK result: payload=%q err=%v", plaintext, err)
			}
		})
	}
}
