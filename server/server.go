package server

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type Server struct {
	baseURL  url.URL
	listener net.Listener

	// Components / interfaces
	accessTokenEnc *accessTokenEncoder

	// Lookups / interfaces
	store     TransientStorage
	authz     Authz
	authn     map[string]Authn
	clientMap ClientMap

	// Concurrency control
	clientMutex sync.RWMutex
	once        sync.Once
	initialized bool
}

// Create a new Server.
func New(options ...Option) (*Server, error) {
	s := &Server{authn: make(map[string]Authn)}
	// First we set options
	for _, option := range options {
		if err := option(s); err != nil {
			return nil, err
		}
	}
	// Set default accesstoken config if not set
	if s.accessTokenEnc == nil {
		log.Println("WARN: accesstoken config missing, using random secret.")
		secret := make([]byte, 16)
		rand.Read(secret)
		s.accessTokenEnc = newAccessTokenEncoder(secret, 36000, "goauth2")
	}
	// Set default transient store if none given
	if s.store == nil {
		log.Println("WARN: Using in-memory transient storage")
		s.store = make(transientMap)
	}
	// Set default scopeset if no authz provider is given
	if s.authz == nil {
		log.Println("WARN: using empty scope set")
		s.authz = &emptyScopeSet{}
	}
	// Set anonymous IdP if none is set
	if len(s.authn) == 0 {
		log.Println("WARN: using anonymous authentication")
		s.authn["anonymous"] = &anonymousIdP{}
	}
	s.initialized = true
	return s, nil
}

// Start() runs the server and reports errors. Ignores subsequent calls after
// the first.
func (s *Server) Start(bindAddr string, errChan chan error) {
	s.once.Do(func() {
		// Create listener
		if listener, err := net.Listen("tcp", bindAddr); err != nil {
			errChan <- err
			return
		} else {
			s.listener = listener
		}
		// Set baseURL to http://listener.addr/ if it isn't set
		if (s.baseURL == url.URL{}) {
			addr := fmt.Sprintf("http://%s/", s.listener.Addr().String())
			if u, err := url.Parse(addr); err != nil {
				errChan <- err
				return
			} else {
				s.baseURL = *u
			}
		}
		// Create handler
		handler, err := s.handler()
		if err != nil {
			errChan <- err
			return
		}
		// Start server
		err = http.Serve(s.listener, handler)
		if err != nil && !strings.Contains(err.Error(), "closed") {
			errChan <- err
		}
	})
}

// Close() closes the listener.
func (s *Server) Close() error {
	return s.listener.Close()
}

// handler() creates the request handler for the server.
func (s *Server) handler() (http.Handler, error) {
	mux := http.NewServeMux()
	idps := make(map[string]*idpHandler)
	pathTempl := "authorize/%s"
	for idpId, authn := range s.authn {
		relPath := fmt.Sprintf(pathTempl, idpId)
		absPath := fmt.Sprintf("/%s", relPath)
		if u, err := s.baseURL.Parse(relPath); err != nil {
			return nil, err
		} else {
			handler := &idpHandler{authn, s.store, u, s.authz, s.accessTokenEnc}
			mux.Handle(absPath, handler)
			idps[idpId] = handler
		}
	}
	// Create authorization handler
	authzHandler := &authorizationHandler{s.clientMap, s.authz, idps}
	mux.Handle("/authorize", authzHandler)
	return mux, nil
}

// Interface TransientStorage is implemented by storage providers and used to
// store transient data throughout the server.
type TransientStorage interface {
	Set(key string, value string, expireIn int) error
	Get(key string) (string, error)
}

// Interface User is implemented by identity providers and used by
// authorization providers.
type User interface {
	// UID() returns the user identifier.
	UID() string
	// Roles() returns a slice of roles associated with this user.
	Roles() []string
}

// Interface Authn is implemented by identity providers.
type Authn interface {
	// AuthnRedirect(...) returns an authentication URL and optional serialized
	// state.
	AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error)
	// User receives the IdP's callback request and returns a User object or
	// an error.
	User(r *http.Request, state []byte) (User, error)
}

// The ScopeSet interface is implemented by authorization providers to allow
// membership tests on its total set of scopes.
type ScopeSet interface {
	// ValidScope() returns true if scope is a subset of this scopeset.
	ValidScope(scope ...string) bool
}

// The Authz interface is implemented by authorization providers to extract a
// user's authorized scopeset and the full scopeset supported by the provider.
type Authz interface {
	ScopeSet
	// ScopeSetFor() returns the given user's authorized scopeset.
	ScopeSetFor(u User) ScopeSet
}

// The Client type contains all data needed for OAuth 2.0 clients.
type Client struct {
	// Client identifier
	Id string
	// list of registered redirects
	Redirects []string
	// client secret
	Secret string
	// Allowed grants (implicit, authz code, client credentials)
	GrantType string
}

// The ClientMap interface is implemented for OAuth 2.0 clients and used to
// authenticate and validate client data provided in all authorization flows.
type ClientMap interface {
	// Returns the client for this identifier or an error
	Get(id string) (*Client, error)
}

// An option is a server option that can be passed to New().
type Option func(*Server) error

// BaseURL() is an option that sets the given URL as the base URL of the
// service. This is useful if the external address of the service is different
// from its bind address (so basically in any environment apart from in
// development).
func BaseURL(u url.URL) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.baseURL = u
		return nil
	}
}

// Storage() is an option that sets the transient storage for the server
// instance.
func Storage(store TransientStorage) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.store = store
		return nil
	}
}

// Clients() is an option that sets the given client mapping for the server
// instance.
func Clients(m ClientMap) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.clientMap = m
		return nil
	}
}

// AuthzProvider() is an option that sets the given authorization provider for
// the server instance.
func AuthzProvider(p Authz) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.authz = p
		return nil
	}
}

// AccessTokenConfig() is an option that configures access token JWTs.
func AccessTokenConfig(secret []byte, lifetime int64, issuer string) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Can only call SetAccessTokenConfig as an option to New(...)")
		}
		s.accessTokenEnc = newAccessTokenEncoder(secret, lifetime, issuer)
		return nil
	}
}

// IdP is an option that adds the given IdP to this server. If the IdP was
// already registered it will be silently overwritten.
func IdP(id string, a Authn) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Can only call RegisterIdP as an option to New(...)")
		}
		s.authn[id] = a
		return nil
	}
}