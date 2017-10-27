package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

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
	Algorithm() string
	Verify(b64header, b64payload, b64digest string) bool
}

type jwtSigner interface {
	jwtVerifier
	Sign(msg []byte) ([]byte, error)
}

// JWKSet manages keys and allows encoding and decoding JWTs.
type JWKSet struct {
	signers   map[string]jwtSigner
	verifiers map[string]jwtVerifier
	kids      []string
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
			jwkSet.kids = append(jwkSet.kids, jwk.KeyID)
			continue
		}
		if jwk, err := unmarshalJWKECPub(key); err == nil { // Check after ECPriv
			jwkSet.verifiers[jwk.KeyID] = jwk
			jwkSet.kids = append(jwkSet.kids, jwk.KeyID)
			continue
		}
		if jwk, err := unmarshalJWKSymmetric(key); err == nil {
			jwkSet.signers[jwk.KeyID] = jwk
			jwkSet.verifiers[jwk.KeyID] = jwk
			jwkSet.kids = append(jwkSet.kids, jwk.KeyID)
			continue
		}
		return nil, fmt.Errorf("Can't use key at index %d (%v)", i, key)
	}
	return jwkSet, nil
}

// KeyIDs returns all key ids in this JWK set in the order they were added.
func (s *JWKSet) KeyIDs() []string {
	return s.kids
}

// Encode creates a JWT from the given data, signed using the key at the given key id.
func (s *JWKSet) Encode(kid string, v interface{}) (string, error) {
	signer, ok := s.signers[kid]
	if !ok {
		return "", fmt.Errorf("Cannot use kid %v to encode", kid)
	}
	jwtHeader := &header{Alg: signer.Algorithm(), Kid: kid}
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
	digest, err := signer.Sign([]byte(fmt.Sprintf("%s.%s", b64header, b64payload)))
	if err != nil {
		return "", err
	}
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
	if ok := verifier.Verify(b64header, b64payload, b64digest); !ok {
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
	HashFunc  func() hash.Hash
	CurveFunc func() elliptic.Curve
	SigLength int
	AlgName   string
}

func unmarshalJWKECPub(data []byte) (*jwkECPub, error) {
	var jwk jwkECPub
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	if jwk.KeyType != "EC" {
		return nil, fmt.Errorf("Invalid kty for public ECDSA key: %s", jwk.KeyType)
	}
	if err := jwk.setParams(); err != nil {
		return nil, err
	}
	pk, err := jwk.publicKey()
	if err != nil {
		return nil, err
	}
	jwk.PublicKey = pk
	return &jwk, nil
}

func (j *jwkECPub) setParams() error {
	switch j.Curve {
	case "P-256":
		j.AlgName = "ES256"
		j.HashFunc = sha256.New
		j.CurveFunc = elliptic.P256
		j.SigLength = 64
	case "P-384":
		j.AlgName = "ES384"
		j.HashFunc = sha512.New384
		j.CurveFunc = elliptic.P384
		j.SigLength = 96
	case "P-521":
		j.AlgName = "ES512"
		j.HashFunc = sha512.New
		j.CurveFunc = elliptic.P521
		j.SigLength = 132
	default:
		return fmt.Errorf("Unsupported EC curve: %v", j.Curve)
	}
	return nil
}

func (j *jwkECPub) Algorithm() string {
	return j.AlgName
}

// Verify verifies the signature as specified in RFC 7518 section 3.4
func (j *jwkECPub) Verify(b64header, b64payload, b64digest string) bool {
	// 1. The JWS Signature value MUST be a 64-octet sequence.  If it is
	//    not a 64-octet sequence, the validation has failed.
	decoded := make([]byte, j.SigLength, j.SigLength)
	if len, err := base64.RawURLEncoding.Decode(decoded, []byte(b64digest)); err != nil || len != j.SigLength {
		return false
	}
	// 2. Extract R and S from signature
	l := j.SigLength >> 1
	r := big.NewInt(0)
	r = r.SetBytes(decoded[:l])
	s := big.NewInt(0)
	s = s.SetBytes(decoded[l:])
	// 3. Validate the signature
	hash := j.HashFunc()
	msg := []byte(fmt.Sprintf("%s.%s", b64header, b64payload))
	if _, err := hash.Write(msg); err != nil {
		return false
	}
	sum := hash.Sum(nil)
	return ecdsa.Verify(j.PublicKey, sum, r, s)
}

func (j *jwkECPub) publicKey() (*ecdsa.PublicKey, error) {
	bx, err := base64.URLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, err
	}
	by, err := base64.URLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, err
	}
	x := big.NewInt(0)
	y := big.NewInt(0)
	x = x.SetBytes(bx)
	y = y.SetBytes(by)
	return &ecdsa.PublicKey{Curve: j.CurveFunc(), X: x, Y: y}, nil
}

// jwkECPriv is a JWK holding a private (and public) ECDSA key (RFC 7518 section 6.2.2)
type jwkECPriv struct {
	jwkECPub
	D          string `json:"d"`
	PrivateKey *ecdsa.PrivateKey
}

func unmarshalJWKECPriv(data []byte) (*jwkECPriv, error) {
	var jwk jwkECPriv
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	if jwk.KeyType != "EC" {
		return nil, fmt.Errorf("Invalid kty for private ECDSA key: %s", jwk.KeyType)
	}
	if err := jwk.setParams(); err != nil {
		return nil, err
	}
	pk, err := jwk.privateKey()
	if err != nil {
		return nil, err
	}
	jwk.PrivateKey = pk
	jwk.PublicKey = &pk.PublicKey
	return &jwk, nil
}

func (j *jwkECPriv) Sign(msg []byte) ([]byte, error) {
	// Write to hash
	hash := j.HashFunc()
	if _, err := hash.Write(msg); err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	// Sign the input
	r, s, err := ecdsa.Sign(rand.Reader, j.PrivateKey, sum)
	if err != nil {
		return nil, err
	}
	// Create fixed-length byte arrays and fill with r and s, big-endian unsigned
	rBytes, sBytes := r.Bytes(), s.Bytes()
	l := j.SigLength >> 1
	rFixed, sFixed := make([]byte, l, l), make([]byte, l, l)
	copy(rFixed[l-len(rBytes):], rBytes)
	copy(sFixed[l-len(sBytes):], sBytes)
	// append r + s and return
	return append(rFixed[:], sFixed[:]...), nil
}

func (j *jwkECPriv) privateKey() (*ecdsa.PrivateKey, error) {
	bd, err := base64.URLEncoding.DecodeString(j.D)
	if err != nil {
		return nil, err
	}
	d := big.NewInt(0)
	d = d.SetBytes(bd)
	pubKey, err := j.publicKey()
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pubKey, D: d,
	}, nil
}

// jwkSymmetric holds a symmetric JWK (RFC 7518 section 6.4)
type jwkSymmetric struct {
	jwkData
	Alg      string `json:"alg"`
	K        string `json:"k"`
	HashFunc func() hash.Hash
}

func unmarshalJWKSymmetric(data []byte) (*jwkSymmetric, error) {
	var jwk jwkSymmetric
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	if jwk.KeyType != "oct" {
		return nil, fmt.Errorf("Invalid kty for symmetric key: %s", jwk.KeyType)
	}
	switch jwk.Alg {
	case "HS256":
		jwk.HashFunc = sha256.New
	case "HS384":
		jwk.HashFunc = sha512.New384
	case "HS512":
		jwk.HashFunc = sha512.New
	default:
		return nil, fmt.Errorf("Invalid Alg for symmetric key: %s", jwk.Alg)
	}
	return &jwk, nil
}

func (j *jwkSymmetric) Algorithm() string {
	return j.Alg
}

func (j *jwkSymmetric) Sign(msg []byte) ([]byte, error) {
	mac := hmac.New(j.HashFunc, []byte(j.K))
	mac.Write(msg)
	return mac.Sum(nil), nil
}

func (j *jwkSymmetric) Verify(b64header, b64payload, b64digest string) bool {
	digest, _ := j.Sign([]byte(fmt.Sprintf("%s.%s", b64header, b64payload)))
	computedB64digest := base64.RawURLEncoding.EncodeToString(digest)
	if b64digest == computedB64digest {
		return true
	}
	return false
}
