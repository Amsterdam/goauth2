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
			{ "kty": "oct", "use": "sig", "kid": "1", "alg": "HS256", "k": "iamasymmetrickey" },
			{ "kty": "oct", "use": "sig", "kid": "2", "alg": "HS384", "k": "iamanothersymmetrickey" },
			{ "kty": "oct", "use": "sig", "kid": "3", "alg": "HS512", "k": "iamyetanothersymmetrickey" }
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
			{ "kty": "EC", "use": "sig", "kid": "1", "crv": "P-256", "x": "g9IULlEyYGp3i2IZ1STiuDQ0rcrt3r3o-01f7_wOM_o=", "y": "8QfpzSUvN4UAI4PliUXpeOv8RwLU8P8qLXqhTCc4w1M=", "d": "dIz2ALAunAxB5ajQVx3fAdbttNX4WazEyvXLyi6BFBc=" },
			{ "kty": "EC", "use": "sig", "kid": "2", "crv": "P-384", "x": "TrW1AvBwiG9yQXojajZYdQXdICVG40rF3MiA1uHBQBWJPJSaZK96mn3dSOal68qp", "y": "-YfvjyA8z2PKlp4bmxFYXHfuvyDkzukU1x4ke_nMQNPOJucQaKCi3A5B7d5us06Z", "d": "7t5FzU5WXd57XnqZOxVGWfK39Zj_2tH7ZfIpnAcXgd6TARtwNR0x6eoGbFpDKfGU" },
			{ "kty": "EC", "use": "sig", "kid": "3", "crv": "P-521", "x": "S1_-FdLHtQFspHvM1kxnDb4zFBX-RJa4QuGGiDo8_Bx3YLQfdInrf0k0IdSc_JKJwL_DMN4o-ucPSN03-egHkq0=", "y": "qlW-GeBB2E0_J7h_QvzjKKr0j6s9_erHGwUD46a0IotsCEbdwqLG4S5pyVBteQtliBpjN_qPf7QQOb-ypnX0xqs=", "d": "AUyZP2jG7MA8xRK3wj_POTXyQgUUk3_PKnl3VH88VmNlEnSfUMY3F4FyovVBePyBl9XYlpLgXyCnPUaCMB59Tb7c" }
		]}
	`)
	privJWKS, err := LoadJWKSet(privateJWKSet)
	if err != nil {
		t.Fatal(err)
	}
	var publicJWKSet = []byte(`
		{ "keys": [
			{ "kty": "EC", "use": "sig", "kid": "1", "crv": "P-256", "x": "g9IULlEyYGp3i2IZ1STiuDQ0rcrt3r3o-01f7_wOM_o=", "y": "8QfpzSUvN4UAI4PliUXpeOv8RwLU8P8qLXqhTCc4w1M=" },
			{ "kty": "EC", "use": "sig", "kid": "2", "crv": "P-384", "x": "TrW1AvBwiG9yQXojajZYdQXdICVG40rF3MiA1uHBQBWJPJSaZK96mn3dSOal68qp", "y": "-YfvjyA8z2PKlp4bmxFYXHfuvyDkzukU1x4ke_nMQNPOJucQaKCi3A5B7d5us06Z" },
			{ "kty": "EC", "use": "sig", "kid": "3", "crv": "P-521", "x": "S1_-FdLHtQFspHvM1kxnDb4zFBX-RJa4QuGGiDo8_Bx3YLQfdInrf0k0IdSc_JKJwL_DMN4o-ucPSN03-egHkq0=", "y": "qlW-GeBB2E0_J7h_QvzjKKr0j6s9_erHGwUD46a0IotsCEbdwqLG4S5pyVBteQtliBpjN_qPf7QQOb-ypnX0xqs=" }
		]}
	`)
	pubJWKS, err := LoadJWKSet(publicJWKSet)
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
		token := encode(t, data, privJWKS, kid)
		decode(t, token, &decoded, pubJWKS)
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
