// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v3"
)

// KeyContext contains context that is used to sign, validation, encrypt and decrypt tokens.
// It is populated in different ways depending on the operation. For example -
//
// 1. Validate	: the SigningKeyID and SigningAlgorithm is based on the JWT header of the incoming token
// 2. Decrypt	: the EncryptionKeyID, EncryptionAlgorithm and EncryptionContentAlgorithm is based on the JWT header of the incoming token
// 3. Generate  : all the properties may be populated. The JWT strategy implementation may sign the token, then optionally encrypt it
type KeyContext struct {
	SigningKeyID               string
	SigningAlgorithm           string
	EncryptionKeyID            string
	EncryptionAlgorithm        string
	EncryptionContentAlgorithm string
	Extra                      map[string]interface{}
}

// Strategy provides the overall strategy interface to sign (generate), encrypt (part of generate), decrypt and validate JWTs.
type Strategy interface {
	Signer

	// GenerateWithSettings signs and optionally encrypts the token based on the context provided
	GenerateWithSettings(ctx context.Context, settings *KeyContext, claims MapClaims, header Mapper) (string, string, error)

	// DecryptWithSettings decrypts the token provided. If the token is not encrypted, the function should return an error.
	DecryptWithSettings(ctx context.Context, settings *KeyContext, token string) (string, error)

	// ValidateWithSettings validates the signed token. If the token is not signed, the function should return an error.
	ValidateWithSettings(ctx context.Context, settings *KeyContext, token string) (string, error)
}

type GetPrivateKeyWithContextFunc func(ctx context.Context, context *KeyContext) (interface{}, error)

// DefaultStrategy is responsible for generating (signing and optionally encrypting), decrypting and validating JWT challenges
type DefaultStrategy struct {
	*DefaultSigner
	GetPrivateKey GetPrivateKeyWithContextFunc
}

func NewDefaultStrategy(GetPrivateKey GetPrivateKeyWithContextFunc) Strategy {
	return &DefaultStrategy{
		DefaultSigner: &DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return GetPrivateKey(ctx, nil)
			},
		},
		GetPrivateKey: GetPrivateKey,
	}
}

// GenerateWithSettings signs and optionally encrypts the token based on the context provided
func (s *DefaultStrategy) GenerateWithSettings(ctx context.Context, settings *KeyContext, claims MapClaims, header Mapper) (string, string, error) {
	// ignoring the signing alg and kid for this implementation and just using the DefaultSigner implementation
	rawToken, sig, err := s.DefaultSigner.Generate(ctx, claims, header)
	if err != nil {
		return "", "", err
	}

	if settings.EncryptionAlgorithm == "" {
		return rawToken, sig, err
	}

	key, err := s.GetPrivateKey(ctx, settings)
	if err != nil {
		return "", "", err
	}

	if t, ok := key.(*jose.JSONWebKey); ok {
		key = t.Key
	}

	var pubKey interface{}
	switch t := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &t.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &t.PublicKey
	case jose.OpaqueSigner:
		pubKey = t.Public()
	default:
		return "", "", fmt.Errorf("unable to decode token. Invalid PrivateKey type %T", key)
	}

	eo := &jose.EncrypterOptions{}
	eo = eo.WithContentType("JWT").WithType("JWT")
	enc, err := jose.NewEncrypter(
		jose.ContentEncryption(settings.EncryptionContentAlgorithm),
		jose.Recipient{
			Algorithm: jose.KeyAlgorithm(settings.EncryptionAlgorithm),
			Key:       pubKey,
			KeyID:     settings.EncryptionKeyID,
		},
		eo)

	if err != nil {
		return "", "", fmt.Errorf("unable to build encrypter; err=%v", err)
	}

	// Encrypt the token
	o, err := enc.Encrypt([]byte(rawToken))
	if err != nil {
		return "", "", fmt.Errorf("encrypting the token failed. err=%v", err)
	}

	// Serialize the encrypted token
	rawToken, err = o.CompactSerialize()
	if err != nil {
		return "", "", fmt.Errorf("serializing the encrypted token failed. err=%v", err)
	}

	return rawToken, sig, err
}

// DecryptWithSettings decrypts the token provided. If the token is not encrypted, the function should return an error.
func (s *DefaultStrategy) DecryptWithSettings(ctx context.Context, settings *KeyContext, token string) (string, error) {

	parsedToken, err := jose.ParseEncrypted(token)
	if err != nil {
		return "", fmt.Errorf("unable to parse the token")
	}

	if settings == nil {
		h := parsedToken.Header
		enc, _ := h.ExtraHeaders[jose.HeaderKey("enc")].(string)
		settings = &KeyContext{
			EncryptionKeyID:            h.KeyID,
			EncryptionAlgorithm:        h.Algorithm,
			EncryptionContentAlgorithm: enc,
		}
	}

	key, err := s.GetPrivateKey(ctx, settings)
	var privateKey interface{}
	switch t := key.(type) {
	case *jose.JSONWebKey:
		privateKey = t.Key
	case jose.JSONWebKey:
		privateKey = t.Key
	case *rsa.PrivateKey:
		privateKey = t
	case *ecdsa.PrivateKey:
		privateKey = t
	case jose.OpaqueSigner:
		switch tt := t.Public().Key.(type) {
		case *rsa.PrivateKey:
			privateKey = t
		case *ecdsa.PrivateKey:
			privateKey = t
		default:
			return "", fmt.Errorf("unsupported private / public key pairs: %T, %T", t, tt)
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", t)
	}

	decrypted, err := parsedToken.Decrypt(privateKey)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// ValidateWithSettings validates the signed token. If the token is not signed, the function should return an error.
func (s *DefaultStrategy) ValidateWithSettings(ctx context.Context, settings *KeyContext, token string) (string, error) {
	// ignoring the signing alg and kid for this implementation and just using the DefaultSigner implementation
	return s.DefaultSigner.Validate(ctx, token)
}
