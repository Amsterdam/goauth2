package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Option is a handler setting that can be passed to Handler().
type Option func(*handler) error

// TraceHeader is an option that sets the name of the header that contains a
// request identifier. If present, logs will contain a field reqID.
func TraceHeader(headerName string) Option {
	return func(s *handler) error {
		s.traceHeader = headerName
		return nil
	}
}

// StateStorage is an option that sets the transient storage for the handler
// instance.
func StateStorage(engine StateKeeper, lifetime time.Duration) Option {
	return func(s *handler) error {
		s.stateStore = newStateStorage(engine, lifetime)
		return nil
	}
}

// Clients is an option that sets the given client mapping for the handler
// instance.
func Clients(m ClientMap) Option {
	return func(s *handler) error {
		s.clientMap = m
		return nil
	}
}

// AuthzProvider is an option that sets the given authorization provider for
// the handler instance.
func AuthzProvider(p Authz) Option {
	return func(s *handler) error {
		s.authz = p
		return nil
	}
}

// JWKID is an option that sets the key id of the JSON Web Key to use for access tokens.
func JWKID(kid string) Option {
	return func(s *handler) error {
		s.accessTokenEnc.KeyID = kid
		return nil
	}
}

// AccessTokenLifetime is an option that sets the lifetime of access tokens.
func AccessTokenLifetime(lifetime int64) Option {
	return func(s *handler) error {
		s.accessTokenEnc.Lifetime = lifetime
		return nil
	}
}

// AccessTokenIssuer is an option that sets the iss property in access tokens.
func AccessTokenIssuer(issuer string) Option {
	return func(s *handler) error {
		s.accessTokenEnc.Issuer = issuer
		return nil
	}
}

// IDProvider is an option that adds the given IdP to this handler. If the IDP was
// already registered it will be silently overwritten.
func IDProvider(i IDP) Option {
	return func(s *handler) error {
		s.idps[i.ID()] = i
		return nil
	}
}

// StateKeeper defines a storage engine used to store transient state data
// throughout the handler.
type StateKeeper interface {
	Persist(key string, data string, lifetime time.Duration) error
	Restore(key string) (string, error)
}

// User holds user data returned from the IDP. We require a UUID because we
// encode it in our access token.
type User struct {
	// UID is the user identifier.
	UID string
	// Data may be used
	Data interface{}
}

// IDP defines an identity provider.
type IDP interface {
	// ID returns the IDP's identifier
	ID() string
	// AuthnRedirect(...) returns an authentication URL and optional serialized
	// state.
	AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error)
	// User receives the IDP's callback request and returns a User object or
	// an error.
	User(r *http.Request, state []byte) (*User, error)
}

// ScopeSet defines a set of scopes.
type ScopeSet interface {
	// ValidScope() returns true if scope is a subset of this scopeset.
	ValidScope(scope ...string) bool
}

// Authz contains an authorization provider's scopes and can map a user on scopes.
type Authz interface {
	ScopeSet
	// ScopeSetFor() returns the given user's authorized scopeset.
	ScopeSetFor(u *User) (ScopeSet, error)
}

// Client contains all data needed for OAuth 2.0 clients.
type Client struct {
	// Client identifier
	ID string
	// list of registered redirects
	Redirects []string
	// client secret
	Secret string
	// Allowed grants (implicit, authz code, client credentials)
	GrantType string
}

// ClientMap defines OAuth 2.0 clients.
type ClientMap interface {
	// Returns the client for this identifier or an error
	Get(id string) (*Client, error)
}

// stateMap is the default StateKeeper
type stateMap struct {
	values   map[string]string
	expiries map[string]time.Time
	mutex    sync.Mutex
}

func newStateMap() *stateMap {
	return &stateMap{
		values:   make(map[string]string),
		expiries: make(map[string]time.Time),
	}
}

func (s *stateMap) Persist(key string, value string, lifetime time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	exp := time.Now().Add(lifetime)
	s.values[key] = value
	s.expiries[key] = exp
	return nil
}

func (s *stateMap) Restore(key string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	val, valOk := s.values[key]
	exp, expOk := s.expiries[key]
	if expOk {
		delete(s.expiries, key)
	}
	if valOk {
		delete(s.values, key)
	}
	if !valOk || !expOk || time.Now().After(exp) {
		return "", fmt.Errorf("key %s not found", key)
	}
	return val, nil
}

// emptyClientMap is the default ClientMap.
type emptyClientMap struct{}

func (m *emptyClientMap) Get(id string) (*Client, error) {
	return nil, errors.New("Unknown client id")
}

// emptyScopeSet is the default ScopeSet.
type emptyScopeSet struct{}

func (p *emptyScopeSet) ScopeSetFor(u *User) (ScopeSet, error) {
	return p, nil
}

func (p *emptyScopeSet) ValidScope(scope ...string) bool {
	return false
}
