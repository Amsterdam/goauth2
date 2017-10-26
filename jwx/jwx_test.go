package jwx

import (
	"reflect"
	"testing"
)

type TestToken struct {
	Stringvalue string
	Intvalue    int
	Listvalue   []int
}

func TestHMACJWK(t *testing.T) {
	var testjwks = []byte(`
		{ "keys": [
			{ "kty": "oct", "use": "sig", "kid": "1", "alg": "HS384", "k": "iamasymmetrickey" }
		]}
	`)
	jwks, err := LoadJWKSet(testjwks)
	if err != nil {
		t.Fatal(err)
	}
	encodeAndDecode(t, jwks, "1")
}

func encodeAndDecode(t *testing.T, jwks *JWKSet, kid string) {
	data := TestToken{
		Stringvalue: "test",
		Intvalue:    1,
		Listvalue: []int{
			0, 1,
		},
	}
	token, err := jwks.Encode(kid, &data)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TestToken
	if err := jwks.Decode(token, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, decoded) {
		t.Fatalf("Decoded token not equal to original: %v (%T) != %v (%T)", decoded, decoded, data, data)
	}
}

func TestBadJWKSet(t *testing.T) {
	var badjwks = []byte(`
		{ "keys": []a}
	`)
	_, err := LoadJWKSet(badjwks)
	if err == nil {
		t.Fatal("Should not succeed")
	}
}

func TestSetWithInvalidJWK(t *testing.T) {
	var badjwks = []byte(`
		{ "keys": [
			{ "kty": "what?", "use": "sig", "kid": "1", "alg": "what?" }
		]}
	`)
	_, err := LoadJWKSet(badjwks)
	if err == nil {
		t.Fatal("Should not succeed")
	}
}
