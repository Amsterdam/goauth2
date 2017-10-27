package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amsterdam/authz/jose"
	log "github.com/sirupsen/logrus"
)

type handler struct {
	callbackURL url.URL

	// Components / interfaces
	accessTokenEnc *accessTokenEncoder
	stateStore     *stateStorage
	authz          Authz
	idps           map[string]IDP
	clientMap      ClientMap
	traceHeader    string
}

// Handler returns an http.Handler that handles OAuth 2.0 requests.
func Handler(baseURL string, jwks string, options ...Option) (http.Handler, error) {
	// Parse base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u, err = u.Parse("oauth2/callback")
	if err != nil {
		return nil, err
	}
	// Create handler
	h := &handler{
		callbackURL: *u,
		idps:        make(map[string]IDP),
	}
	// Create JWKSet
	jwkset, err := jose.LoadJWKSet([]byte(jwks))
	if err != nil {
		log.Fatal(err)
	}
	// Create accesstoken encoder
	ate, err := newAccessTokenEncoder(jwkset)
	if err != nil {
		return nil, err
	}
	h.accessTokenEnc = ate
	// Set options
	for _, option := range options {
		if err := option(h); err != nil {
			return nil, err
		}
	}
	// Set default transient store if none given
	if h.stateStore == nil {
		log.Warnln("Using in-memory state storage")
		h.stateStore = newStateStorage(newStateMap(), 60*time.Second)
	} else {
		h.checkStateStore()
	}
	// Set default scopeset if no authz provider is given
	if h.authz == nil {
		log.Warnln("using empty scope set")
		h.authz = &emptyScopeSet{}
	}
	// Set default clientmap if no ClientMap is given
	if h.clientMap == nil {
		log.Warnln("no clientmap given")
		h.clientMap = &emptyClientMap{}
	}
	// Warn if no IdP is set
	if len(h.idps) == 0 {
		log.Warnln("no IDP registered")
	}
	// Create and return handler
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", h.serveAuthorizationRequest)
	mux.HandleFunc("/oauth2/callback", h.serveIDPCallback)
	return mux, nil
}

// checkStateStore makes sure a key / value pair is only restored once
func (h *handler) checkStateStore() {
	if err := h.stateStore.persist("test", struct{}{}); err != nil {
		log.Fatalf("State storage not working: %v\n", err)
	}
	if err := h.stateStore.restore("test", &struct{}{}); err != nil {
		log.Fatalf("State storage not working: %v\n", err)
	}
	if err := h.stateStore.restore("test", &struct{}{}); err == nil {
		log.Fatal("State storage not working: doesn't remove key on first restore")
	}
}

func (h *handler) logger(r *http.Request) *log.Entry {
	logFields := log.Fields{}
	if h.traceHeader != "" {
		logFields["reqID"] = r.Header.Get(h.traceHeader)
	}
	return log.WithFields(logFields)
}

// serveAuthorizationRequest handles an initial authorization request
func (h *handler) serveAuthorizationRequest(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != "GET" {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	// Create context logger
	logFields := log.Fields{
		"type": "authorization request",
		"uri":  r.RequestURI,
	}
	logger := h.logger(r).WithFields(logFields)
	// state of authz request
	authzState := &authorizationState{}
	var (
		query  = r.URL.Query()
		client *Client
		idp    IDP
	)
	// client_id
	if clientID, ok := query["client_id"]; ok {
		authzState.ClientID = clientID[0]
		if c, err := h.clientMap.Get(authzState.ClientID); err == nil {
			client = c
		} else {
			http.Error(w, "invalid client_id", http.StatusBadRequest)
			logger.Infoln("invalid client_id")
			return
		}
	} else {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		logger.Infoln("missing client_id")
		return
	}
	// redirect_uri
	if redir, ok := query["redirect_uri"]; ok {
		for _, r := range client.Redirects {
			if redir[0] == r {
				authzState.RedirectURI = r
				break
			}
		}
	} else if len(client.Redirects) == 1 {
		authzState.RedirectURI = client.Redirects[0]
	}
	if authzState.RedirectURI == "" {
		http.Error(w, "missing or invalid redirect_uri", http.StatusBadRequest)
		logger.Infoln("missing or invalid redirect_uri")
		return
	}
	redirectURI, err := url.Parse(authzState.RedirectURI)
	if err != nil {
		logger.WithError(err).Errorln("Registered redirect is invalid")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// response_type
	responseType, ok := query["response_type"]
	if !ok {
		h.errorResponse(w, redirectURI, "invalid_request", "response_type missing")
		logger.Infoln("invalid_request: response_type missing")
		return
	}
	if responseType[0] != client.GrantType {
		h.errorResponse(
			w, redirectURI, "unsupported_response_type",
			"response_type not supported for client",
		)
		logger.Infoln("unsupported_response_type: response_type not supported for client")
		return
	}
	authzState.ResponseType = client.GrantType
	// state
	if s, ok := query["state"]; ok {
		authzState.State = s[0]
	}
	// scope
	scopeMap := make(map[string]struct{})
	if s, ok := query["scope"]; ok {
		for _, scope := range strings.Split(s[0], " ") {
			if !h.authz.ValidScope(scope) {
				h.errorResponse(
					w, redirectURI, "invalid_scope",
					fmt.Sprintf("invalid scope: %s", scope),
				)
				logger.Infof("invalid scope: %s", scope)
				return
			}
			scopeMap[scope] = struct{}{}
		}
	}
	authzState.Scope = make([]string, len(scopeMap))
	i := 0
	for k := range scopeMap {
		authzState.Scope[i] = k
		i++
	}
	// Validate IDP and get idp handler url for this request
	if idpID, ok := query["idp_id"]; ok {
		authzState.IDPID = idpID[0]
		if idp, ok = h.idps[authzState.IDPID]; !ok {
			h.errorResponse(w, redirectURI, "invalid_request", "unknown idp_id")
			logger.Infoln("invalid_request: unknown idp_id")
			return
		}
	} else {
		h.errorResponse(w, redirectURI, "invalid_request", "idp_id missing")
		logger.Infoln("invalid_request: idp_id missing")
		return
	}
	// Create authn session
	authnRedirect, err := h.authnSession(idp, authzState)
	if err != nil {
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		logger.WithError(err).Errorln("Couldn't save session")
		return
	}

	w.Header().Set("Location", authnRedirect)
	w.WriteHeader(http.StatusSeeOther)
	logger.Infoln("Redirected to IdP")
}

// serveIDPCallback handles IDP callbacks
func (h *handler) serveIDPCallback(w http.ResponseWriter, r *http.Request) {
	// Create context logger
	logFields := log.Fields{
		"type": "idp callback request",
	}
	logger := h.logger(r).WithFields(logFields)
	// Handle request
	q := r.URL.Query()
	token, ok := q["token"]
	if !ok {
		http.Error(w, "token parameter missing", http.StatusBadRequest)
		logger.Infoln("token parameter missing")
		return
	}
	var state authorizationState
	if err := h.stateStore.restore(token[0], &state); err != nil {
		logger.WithError(err).Errorln("Error restoring state")
		http.Error(w, "invalid state token", http.StatusBadRequest)
		return
	}
	redirectURI, err := url.Parse(state.RedirectURI)
	if err != nil {
		logger.WithError(err).Errorf("Error reconstructing redirect_uri from unmarshalled state: %v\n", state.RedirectURI)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	idp, ok := h.idps[state.IDPID]
	if !ok {
		logger.Errorf("Invalid IDP (authzrequest should have failed): %s\n", state.IDPID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := idp.User(r, state.IDPState)
	if err != nil {
		logger.WithError(err).Infoln("Error authenticating user")
		h.errorResponse(w, redirectURI, "access_denied", "couldn't authenticate user")
		return
	}
	grantedScopes := []string{}
	if len(state.Scope) > 0 {
		userScopes, err := h.authz.ScopeSetFor(user)
		if err != nil {
			logger.WithError(err).Errorln("Error getting scopes for user")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for _, scope := range state.Scope {
			if userScopes.ValidScope(scope) {
				grantedScopes = append(grantedScopes, scope)
			}
		}
	}
	accessToken, err := h.accessTokenEnc.Encode(user.UID, grantedScopes)
	if err != nil {
		logger.WithError(err).Errorln("Error encoding accesstoken")
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}
	h.implicitResponse(
		w, redirectURI, accessToken, "bearer", h.accessTokenEnc.Lifetime,
		grantedScopes, state.State,
	)
	// Auditlog
	sigIdx := strings.LastIndex(accessToken, ".") + 1
	logger.WithFields(log.Fields{
		"sub":            user.UID,
		"tokensignature": accessToken[sigIdx:],
		"scopes":         grantedScopes,
		"expires_in":     h.accessTokenEnc.Lifetime,
	}).Info("User authorized")
}

// authnSession saves the current state of the authorization request and
// returns a redirect URL for the given idp
func (h *handler) authnSession(idp IDP, state *authorizationState) (string, error) {
	// Create token
	token := make([]byte, 16)
	rand.Read(token)
	b64Token := base64.RawURLEncoding.EncodeToString(token)
	// Add token to callback URL
	query := url.Values{}
	query.Set("token", b64Token)
	callbackURL := h.callbackURL
	callbackURL.RawQuery = query.Encode()
	// Het authentication redirect
	redir, idpState, err := idp.AuthnRedirect(&callbackURL)
	if err != nil {
		return "", err
	}
	state.IDPState = idpState
	if err := h.stateStore.persist(b64Token, state); err != nil {
		return "", err
	}
	return redir.String(), nil
}

// oauth20Error
func (h *handler) errorResponse(
	w http.ResponseWriter, r *url.URL, code string, desc string) {
	query := r.Query()
	query.Set("error", code)
	query.Set("error_description", desc)
	r.RawQuery = query.Encode()
	headers := w.Header()
	headers.Add("Location", r.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (h *handler) implicitResponse(
	w http.ResponseWriter, redirectURI *url.URL, accessToken string,
	tokenType string, lifetime int64, scope []string, state string) {
	v := url.Values{}
	v.Set("access_token", accessToken)
	v.Set("token_type", tokenType)
	v.Set("expires_in", fmt.Sprintf("%d", lifetime))
	v.Set("scope", strings.Join(scope, " "))
	if len(state) > 0 {
		v.Set("state", state)
	}
	fragment := v.Encode()
	redir := fmt.Sprintf("%s#%s", redirectURI.String(), fragment)
	w.Header().Add("Location", redir)
	w.WriteHeader(http.StatusSeeOther)
}
