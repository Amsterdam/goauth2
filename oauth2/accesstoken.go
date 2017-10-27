package oauth2

import (
	"errors"
	"time"

	"github.com/amsterdam/authz/jose"

	"github.com/google/uuid"
)

type accessTokenPayload struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	JWTId     string   `json:"jti"`
	Scopes    []string `json:"scopes"`
}

type accessTokenEncoder struct {
	jwks     *jose.JWKSet
	Lifetime int64
	Issuer   string
	KeyID    string
}

func newAccessTokenEncoder(jwks *jose.JWKSet) (*accessTokenEncoder, error) {
	kids := jwks.KeyIDs()
	if len(kids) < 1 {
		return nil, errors.New("JWK set must contain at least one key")
	}
	return &accessTokenEncoder{jwks: jwks, Lifetime: 60, KeyID: kids[0]}, nil
}

func (enc *accessTokenEncoder) Encode(subject string, scopes []string) (string, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	payload := &accessTokenPayload{
		Issuer:    enc.Issuer,
		Subject:   subject,
		IssuedAt:  now,
		NotBefore: now - 10,
		ExpiresAt: now + enc.Lifetime,
		JWTId:     jti.String(),
		Scopes:    scopes,
	}
	return enc.jwks.Encode(enc.KeyID, payload)
}
