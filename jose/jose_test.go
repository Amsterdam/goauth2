package jose

import (
	"reflect"
	"testing"
)

type TestToken struct {
	Stringvalue string
	Intvalue    int
	Listvalue   []int
}

func TestJWKHMAC(t *testing.T) {
	var jwkSet = []byte(`
		{ "keys": [
			{ "kty": "oct", "use": "sig", "key_ops": ["sign", "verify"], "kid": "1", "alg": "HS256", "k": "iamasymmetrickey" },
			{ "kty": "oct", "use": "sig", "key_ops": ["sign", "verify"], "kid": "2", "alg": "HS384", "k": "iamanothersymmetrickey" },
			{ "kty": "oct", "use": "sig", "key_ops": ["sign", "verify"], "kid": "3", "alg": "HS512", "k": "iamyetanothersymmetrickey" }
		]}
	`)
	jwks, err := LoadJWKSet(jwkSet)
	if err != nil {
		t.Fatal(err)
	}
	data := TestToken{
		Stringvalue: "test",
		Intvalue:    1,
		Listvalue: []int{
			0, 1,
		},
	}
	for _, kid := range []string{"1", "2", "3"} {
		var decoded TestToken
		decode(t, encode(t, data, jwks, kid), &decoded, jwks)
		if !reflect.DeepEqual(data, decoded) {
			t.Fatalf("Decoded token not equal to original: %v (%T) != %v (%T)", decoded, decoded, data, data)
		}
	}
}

func TestJWKEC(t *testing.T) {
	var privateJWKSet = []byte(`
		{ "keys": [
			{ "kty": "EC", "use": "sig", "key_ops": ["sign", "verify"], "kid": "1", "crv": "P-256", "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4=", "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU=", "d":"9GJquUJf57a9sev-u8-PoYlIezIPqI_vGpIaiu4zyZk=" },
			{ "kty": "EC", "use": "sig", "key_ops": ["sign", "verify"], "kid": "2", "crv": "P-384", "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J", "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy", "d": "xKPj5IXjiHpQpLOgyMGo6lg_DUp738SuXkiugCFMxbGNKTyTprYPfJz42wTOXbtd" },
			{ "kty": "EC", "use": "sig", "key_ops": ["sign", "verify"], "kid": "3", "crv": "P-521", "x": "AKarqFSECj9mH4scD_RSGD1lzBzomFWz63hvqDc8PkElCKByOUIo_N8jN5mpJS2RfbIj2d9bEDnpwQGLvu9kXG97", "y": "AF5ZmIGpat-yKHoP985gfnASPPZuhXGqPg4QdsJzdV4sY1GP45DOxwjZOmvhOzKzezmB-SSOWweMgUDNHoJreAXQ", "d": "ALV2ghdOJbsaT4QFwqbOky6TwkHEC89pQ-bUe7kt5A7-8vXI2Ihi2YEtygCQ5PwtPiTxjRs5mgzVDRp5LwHyYzvn" }
		]}
	`)
	jwks, err := LoadJWKSet(privateJWKSet)
	if err != nil {
		t.Fatal(err)
	}
	data := TestToken{
		Stringvalue: "test",
		Intvalue:    1,
		Listvalue: []int{
			0, 1,
		},
	}
	for _, kid := range []string{"1", "2", "3"} {
		var decoded TestToken
		token := encode(t, data, jwks, kid)
		t.Log(token)
		decode(t, token, &decoded, jwks)
		if !reflect.DeepEqual(data, decoded) {
			t.Fatalf("Decoded token not equal to original: %v (%T) != %v (%T)", decoded, decoded, data, data)
		}
	}
}

func encode(t *testing.T, data interface{}, jwks *JWKSet, kid string) string {
	token, err := jwks.Encode(kid, &data)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func decode(t *testing.T, token string, v interface{}, jwks *JWKSet) {
	if err := jwks.Decode(token, v); err != nil {
		t.Fatal(err)
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
