package jwx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

var hmacAlgorithms = map[string]func() hash.Hash{
	"HS256": sha256.New,
	"HS384": sha512.New384,
	"HS512": sha512.New,
}

var ecAlgorithms = map[string]*ecAlgorithm{
	"ES256": &ecAlgorithm{
		Curve: elliptic.P256,
		Hash:  sha256.New,
	},
	"ES384": &ecAlgorithm{
		Curve: elliptic.P384,
		Hash:  sha512.New384,
	},
	"ES512": &ecAlgorithm{
		Curve: elliptic.P521,
		Hash:  sha512.New,
	},
}

type ecAlgorithm struct {
	Curve func() elliptic.Curve
	Hash  func() hash.Hash
}

// header is a JWT header
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwks represents a JSON Web Key Set (RFC 7517 section 5). Used for unmarshalling.
type jwks struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwtVerifier interface {
	algorithm() string
	verify(b64header, b64payload, b64digest string) bool
}

type jwtSigner interface {
	jwtVerifier
	sign(msg []byte) []byte
}

// JWKSet manages keys and allows encoding and decoding JWTs.
type JWKSet struct {
	signers   map[string]jwtSigner
	verifiers map[string]jwtVerifier
}

// LoadJWKSet creates a JWKSet using the given json-encoded data
func LoadJWKSet(data []byte) (*JWKSet, error) {
	var keyset jwks
	if err := json.Unmarshal(data, &keyset); err != nil {
		return nil, err
	}
	jwkSet := &JWKSet{
		signers:   make(map[string]jwtSigner),
		verifiers: make(map[string]jwtVerifier),
	}
	for i, key := range keyset.Keys {
		if jwk, err := unmarshalJWKECPriv(key); err == nil { // Check before ECPub
			jwkSet.signers[jwk.KeyID] = jwk
			jwkSet.verifiers[jwk.KeyID] = jwk
			continue
		}
		if jwk, err := unmarshalJWKECPub(key); err == nil { // Check after ECPriv
			jwkSet.verifiers[jwk.KeyID] = jwk
			continue
		}
		if jwk, err := unmarshalJWKSymmetric(key); err == nil {
			jwkSet.signers[jwk.KeyID] = jwk
			jwkSet.verifiers[jwk.KeyID] = jwk
			continue
		}
		return nil, fmt.Errorf("Can't use key at index %d (%v)", i, key)
	}
	return jwkSet, nil
}

// Encode creates a JWT from the given data, signed using the key at the given key id.
func (s *JWKSet) Encode(kid string, v interface{}) (string, error) {
	signer, ok := s.signers[kid]
	if !ok {
		return "", fmt.Errorf("Cannot use kid %v to encode", kid)
	}
	jwtHeader := &header{Alg: signer.algorithm(), Kid: kid}
	headerJSON, err := json.Marshal(jwtHeader)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	b64header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := signer.sign([]byte(fmt.Sprintf("%s.%s", b64header, b64payload)))
	b64digest := base64.RawURLEncoding.EncodeToString(digest)
	return fmt.Sprintf("%s.%s.%s", b64header, b64payload, b64digest), nil
}

// Decode verifies the given data (JWT) and decodes it into v.
func (s *JWKSet) Decode(data string, v interface{}) error {
	// split the JWT
	parts := strings.Split(data, ".")
	if len(parts) != 3 {
		return fmt.Errorf("JWT shoud have 3 parts, has %d: ", len(parts))
	}
	b64header, b64payload, b64digest := parts[0], parts[1], parts[2]
	// decode the header
	rawHeader, err := base64.RawURLEncoding.DecodeString(b64header)
	if err != nil {
		return err
	}
	jwtHeader := header{}
	if err = json.Unmarshal(rawHeader, &jwtHeader); err != nil {
		return err
	}
	// Grab the correct verifier
	verifier, ok := s.verifiers[jwtHeader.Kid]
	if !ok {
		return fmt.Errorf("No key with ID %v available in keyset for verification", jwtHeader.Kid)
	}
	// Verify
	if ok := verifier.verify(b64header, b64payload, b64digest); !ok {
		return errors.New("Couldn't verify JWT")
	}
	// Decode payload into v
	rawPayload, err := base64.RawURLEncoding.DecodeString(b64payload)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(rawPayload, v); err != nil {
		return err
	}
	return nil
}

// jwkData holds data common to all JWKs (RFC 7517 section 4)
type jwkData struct {
	KeyType string `json:"kty"`
	Use     string `json:"use"`
	KeyID   string `json:"kid"`
}

// jwkECPub is a JWK holding a public ECDSA key (RFC 7518 section 6.2.1)
type jwkECPub struct {
	jwkData
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
	PublicKey *ecdsa.PublicKey
}

func unmarshalJWKECPub(data []byte) (*jwkECPub, error) {
	var jwk jwkECPub
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	if jwk.KeyType != "EC" {
		return nil, fmt.Errorf("Invalid kty for symmetric key: %s", jwk.KeyType)
	}
	_, ok := ecAlgorithms[jwk.algorithm()]
	if !ok {
		return nil, fmt.Errorf("Unsupported algorithm: %v", jwk.algorithm())
	}
	return &jwk, nil
}

func (j *jwkECPub) algorithm() string {
	var alg string
	switch j.Curve {
	case "P-256":
		alg = "ES256"
	case "P-384":
		alg = "ES384"
	case "P-521":
		alg = "ES512"
	}
	return alg
}

func (j *jwkECPub) publicKey() (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, err
	}
	var x64, y64 int64
	if err := binary.Read(bytes.NewReader(x), binary.BigEndian, &x64); err != nil {
		return nil, err
	}
	if err := binary.Read(bytes.NewReader(y), binary.BigEndian, &y64); err != nil {
		return nil, err
	}
	curve, err := j.curve()
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve(), X: big.NewInt(x64), Y: big.NewInt(y64),
	}, nil
}

func (j *jwkECPub) curve() (func() elliptic.Curve, error) {
	ecAlg, ok := ecAlgorithms[j.algorithm()]
	if !ok {
		return nil, fmt.Errorf("Unsupported algorithm: %v", j.algorithm())
	}
	return ecAlg.Curve, nil
}

func (j *jwkECPub) hash() (func() hash.Hash, error) {
	ecAlg, ok := ecAlgorithms[j.algorithm()]
	if !ok {
		return nil, fmt.Errorf("Unsupported algorithm: %v", j.algorithm())
	}
	return ecAlg.Hash, nil
}

func (j *jwkECPub) verify(b64header, b64payload, b64digest string) bool {
	return false
}

// jwkECPriv is a JWK holding a private (and public) ECDSA key (RFC 7518 section 6.2.2)
type jwkECPriv struct {
	jwkECPub
	D string `json:"d"`
}

func unmarshalJWKECPriv(data []byte) (*jwkECPriv, error) {
	var jwk jwkECPriv
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	if jwk.KeyType != "EC" {
		return nil, fmt.Errorf("Invalid kty for symmetric key: %s", jwk.KeyType)
	}
	_, ok := ecAlgorithms[jwk.algorithm()]
	if !ok {
		return nil, fmt.Errorf("Unsupported algorithm: %v", jwk.algorithm())
	}
	return &jwk, nil
}

func (j *jwkECPriv) sign(msg []byte) []byte {
	return nil
}

func (j *jwkECPriv) privateKey() (*ecdsa.PrivateKey, error) {
	d, err := base64.RawURLEncoding.DecodeString(j.D)
	if err != nil {
		return nil, err
	}
	var d64 int64
	if err := binary.Read(bytes.NewReader(d), binary.BigEndian, &d64); err != nil {
		return nil, err
	}
	pubKey, err := j.publicKey()
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pubKey, D: big.NewInt(d64),
	}, nil
}

// jwkSymmetric holds a symmetric JWK (RFC 7518 section 6.4)
type jwkSymmetric struct {
	jwkData
	Alg string `json:"alg"`
	K   string `json:"k"`
}

func unmarshalJWKSymmetric(data []byte) (*jwkSymmetric, error) {
	var jwk jwkSymmetric
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	if jwk.KeyType != "oct" {
		return nil, fmt.Errorf("Invalid kty for symmetric key: %s", jwk.KeyType)
	}
	if _, ok := hmacAlgorithms[jwk.Alg]; !ok {
		return nil, fmt.Errorf("Invalid algorithm for symmetric key: %s", jwk.Alg)
	}
	return &jwk, nil
}

func (j *jwkSymmetric) algorithm() string {
	return j.Alg
}

func (j *jwkSymmetric) sign(msg []byte) []byte {
	mac := hmac.New(hmacAlgorithms[j.Alg], []byte(j.K))
	mac.Write(msg)
	return mac.Sum(nil)
}

func (j *jwkSymmetric) verify(b64header, b64payload, b64digest string) bool {
	digest := j.sign([]byte(fmt.Sprintf("%s.%s", b64header, b64payload)))
	computedB64digest := base64.RawURLEncoding.EncodeToString(digest)
	if b64digest == computedB64digest {
		return true
	}
	return false
}
