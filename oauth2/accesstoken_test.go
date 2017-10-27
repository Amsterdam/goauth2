package oauth2

import (
	"reflect"
	"testing"

	"github.com/amsterdam/authz/jose"
)

func makeEncoder() (*accessTokenEncoder, *jose.JWKSet, error) {
	var jwks = []byte(`
		{ "keys": [
			{ "kty": "EC", "use": "sig", "kid": "1", "crv": "P-256", "x": "g9IULlEyYGp3i2IZ1STiuDQ0rcrt3r3o-01f7_wOM_o=", "y": "8QfpzSUvN4UAI4PliUXpeOv8RwLU8P8qLXqhTCc4w1M=", "d": "dIz2ALAunAxB5ajQVx3fAdbttNX4WazEyvXLyi6BFBc=" }
		]}
	`)
	jwkSet, err := jose.LoadJWKSet(jwks)
	if err != nil {
		return nil, nil, err
	}
	enc, err := newAccessTokenEncoder(jwkSet)
	if err != nil {
		return nil, nil, err
	}
	return enc, jwkSet, nil
}

func TestEncode(t *testing.T) {
	var (
		subject = "subject"
		scopes  = []string{"scope1", "scope2"}
	)
	enc, jwks, err := makeEncoder()
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := enc.Encode(subject, scopes)
	if err != nil {
		t.Fatal(err)
	}
	var decoded accessTokenPayload
	if err := jwks.Decode(jwt, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Subject != subject {
		t.Fatalf("JWT subject doesn't match (expected: %s, got %s)", subject, decoded.Subject)
	}
	if !reflect.DeepEqual(scopes, decoded.Scopes) {
		t.Fatalf("Scopes dont match (expected: %s, got %s)", scopes, decoded.Scopes)
	}
}

func BenchmarkEncode(b *testing.B) {
	enc, _, err := makeEncoder()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encode("subject", []string{"abc", "def"}); err != nil {
			b.Fatal(err)
		}
	}
}
