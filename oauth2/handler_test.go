package oauth2

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type testAuthzRequest struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	State        string
	Scope        []string
	IDPID        string
	Validate     func(r *http.Response)
}

func (r *testAuthzRequest) Do(handler http.Handler) {
	req := httptest.NewRequest("GET", "http://test/oauth2/authorize", nil)
	q := req.URL.Query()
	if r.ClientID != "" {
		q.Set("client_id", r.ClientID)
	}
	if r.RedirectURI != "" {
		q.Set("redirect_uri", r.RedirectURI)
	}
	if r.ResponseType != "" {
		q.Set("response_type", r.ResponseType)
	}
	if r.State != "" {
		q.Set("state", r.State)
	}
	if len(r.Scope) > 0 {
		q.Set("scope", strings.Join(r.Scope, " "))
	}
	if r.IDPID != "" {
		q.Set("idp_id", r.IDPID)
	}
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	r.Validate(w.Result())
}

func TestAuthorizationHandler(t *testing.T) {
	var tests = []*testAuthzRequest{
		// No input at all
		&testAuthzRequest{
			Validate: func(r *http.Response) {
				expectBadRequest(
					"no parameters", t, r, "missing client_id\n",
				)
			},
		},
		// Invalid client_id
		&testAuthzRequest{
			ClientID: "bad",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"invalid redirect_uri", t, r, "invalid client_id\n",
				)
			},
		},
		// Missing redirect_uri
		&testAuthzRequest{
			ClientID: "testclient2",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"missing redirect_uri", t, r, "missing or invalid redirect_uri\n",
				)
			},
		},
		// Bad redirect_uri
		&testAuthzRequest{
			ClientID:    "testclient1",
			RedirectURI: "http://bad/",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"bad redirect_uri", t, r, "missing or invalid redirect_uri\n",
				)
			},
		},
		// Invalid redirect_uri (should be caught at client registration as well)
		&testAuthzRequest{
			ClientID:    "testclient2",
			RedirectURI: ":",
			Validate: func(r *http.Response) {
				if r.StatusCode != 500 {
					t.Fatalf(
						"invalid redirect_uri: got %d, expected 500", r.StatusCode,
					)
				}
			},
		},
		// Missing response_type
		&testAuthzRequest{
			ClientID: "testclient1",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"missing response_type", t, r, "invalid_request",
					"response_type missing",
				)
			},
		},
		// Unspported response_type
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "code",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"unsupported response_type", t, r, "unsupported_response_type",
					"response_type not supported for client",
				)
			},
		},
		// Invalid scope
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			Scope:        []string{"scope:1", "thisisnoscope"},
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"invalid scope", t, r, "invalid_scope", "invalid scope: thisisnoscope",
				)
			},
		},
		// Missing idp_id
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"missing idp_id", t, r, "invalid_request", "idp_id missing",
				)
			},
		},
		// Unknown idp_id
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			IDPID:        "invalid",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"unknown idp_id", t, r, "invalid_request", "unknown idp_id",
				)
			},
		},
		// Successful request
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			IDPID:        "testidp",
			Validate: func(r *http.Response) {
				if r.StatusCode != 303 {
					t.Fatalf(
						"valid request: Unexpected response (expected 303, got %d)",
						r.StatusCode,
					)
				}
			},
		},
	}
	handler := testHandler("test")
	for _, test := range tests {
		test.Do(handler)
	}
}

func TestEmptyCallbackRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/oauth2/callback", nil)
	w := httptest.NewRecorder()
	handler := testHandler("test")
	handler.ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("empty callback", t, resp, "token parameter missing\n")
}

func TestInvalidCallbackToken(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/oauth2/callback?token=test", nil)
	w := httptest.NewRecorder()
	handler := testHandler("test")
	handler.ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("invalid callback token", t, resp, "invalid state token\n")
}

func TestValidCallbackToken(t *testing.T) {
	handler := testHandler("test")
	// First, make a valid authz request to get a valid token
	callback := validCallbackURL(t, handler)
	// Now make the valid callback request
	callbackReq := httptest.NewRequest("GET", callback, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, callbackReq)
	resp := w.Result()
	if resp.StatusCode != 303 {
		t.Fatalf(
			"valid callback token: Unexpected response (expected 303, got %d)",
			resp.StatusCode,
		)
	}
	locationHeaders, ok := resp.Header["Location"]
	if !ok {
		t.Fatalf("valid callback token: Unexpected response: %v", resp)
	}
	location := locationHeaders[0]
	if u, err := url.Parse(location); err != nil {
		t.Fatalf("valid callback token: Bad location: %v", err)
	} else {
		params, err := url.ParseQuery(u.Fragment)
		if err != nil {
			t.Fatalf("valid callback token: expected an accesstoken fragment: %v", u)
		}
		if _, ok := params["access_token"]; !ok {
			t.Fatalf("valid callback token: expected an accesstoken fragment: %v", u)
		}
	}
}

func validCallbackURL(t *testing.T, handler http.Handler) string {
	authzReq := httptest.NewRequest("GET", "http://test/oauth2/authorize", nil)
	q := authzReq.URL.Query()
	q.Set("client_id", "testclient1")
	q.Set("redirect_uri", "http://testclient/")
	q.Set("response_type", "token")
	q.Set("state", "state")
	q.Set("scope", "scope:1 scope:2 scope:3")
	q.Set("idp_id", "testidp")
	authzReq.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authzReq)
	r := w.Result()
	locationHeaders, ok := r.Header["Location"]
	if !ok {
		t.Fatalf("creating callback url: Unexpected response: %v", r)
	}
	location := locationHeaders[0]
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("creating callback url: Bad location: %v", err)
	} else if !strings.HasSuffix(u.Path, "/callback") {
		t.Fatalf(
			"creating callback url: Expected to be redirected back to authz callback, got %s instead",
			location,
		)
	}
	q = u.Query()
	q.Set("uid", "user:1")
	u.RawQuery = q.Encode()
	return u.String()
}

func testHandler(tokenSecret string) http.Handler {
	var options []Option
	// IDP with two users
	idp := &testIDP{
		&User{UID: "user:1"},
		&User{UID: "user:2"},
	}
	options = append(options, IDProvider(idp))
	// Clients
	clients := testClientMap{
		&Client{
			ID:        "testclient1",
			Redirects: []string{"http://testclient/"},
			GrantType: "token",
		},
		&Client{
			ID:        "testclient2",
			Redirects: []string{"http://testclient2/a", ":"},
			GrantType: "token",
		},
	}
	options = append(options, Clients(clients))
	// Authorization provider
	authz := newTestAuthz(map[string][]string{
		"user:1": []string{"scope:1", "scope:2"},
		"user:2": []string{"scope:2", "scope:3"},
	})
	options = append(options, AuthzProvider(authz))
	var jwks = `
		{ "keys": [
			{ "kty": "EC", "use": "sig", "kid": "1", "crv": "P-256", "x": "g9IULlEyYGp3i2IZ1STiuDQ0rcrt3r3o-01f7_wOM_o=", "y": "8QfpzSUvN4UAI4PliUXpeOv8RwLU8P8qLXqhTCc4w1M=", "d": "dIz2ALAunAxB5ajQVx3fAdbttNX4WazEyvXLyi6BFBc=" }
		]}
	`
	handler, _ := Handler("http://test/", jwks, options...)
	return handler
}

///////
// testIDP
///////
type testIDP []*User

func (a testIDP) ID() string {
	return "testidp"
}

func (a testIDP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

func (a testIDP) User(r *http.Request, state []byte) (*User, error) {
	uid, ok := r.URL.Query()["uid"]
	if !ok {
		return nil, errors.New("Unknown uid")
	}
	for _, u := range a {
		if u.UID == uid[0] {
			return u, nil
		}
	}
	return nil, errors.New("Invalid state")
}

///////
// testClientMap
///////
type testClientMap []*Client

func (m testClientMap) Get(id string) (*Client, error) {
	for _, c := range m {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, errors.New("unknown client")
}

///////
// A mock authorization provider type
///////
type testAuthz struct {
	users  map[string][]string
	scopes map[string]struct{}
}

func newTestAuthz(users map[string][]string) *testAuthz {
	t := &testAuthz{}
	t.users = users
	t.scopes = make(map[string]struct{})
	for _, scopes := range users {
		for _, scope := range scopes {
			t.scopes[scope] = struct{}{}
		}
	}
	return t
}

func (a testAuthz) ValidScope(scope ...string) bool {
	for _, s := range scope {
		if _, ok := a.scopes[s]; !ok {
			return false
		}
	}
	return true
}

// Create scopeset for the given user
func (a testAuthz) ScopeSetFor(u *User) (ScopeSet, error) {
	scopes, ok := a.users[u.UID]
	if !ok {
		return nil, fmt.Errorf("User %s not found", u.UID)
	}
	return newTestAuthz(map[string][]string{u.UID: scopes}), nil
}

///////
// Helpers
///////
func expectErrorResponse(
	title string, t *testing.T, r *http.Response, code string, description string) {
	if r.StatusCode != 303 {
		t.Fatalf(
			"%s: Unexpected response (expected 303, got %d)", title, r.StatusCode,
		)
	}
	location, ok := r.Header["Location"]
	if !ok {
		t.Fatalf("%s: HTTP 303 without Location header", title)
	}
	u, err := url.Parse(location[0])
	if err != nil {
		t.Fatalf("%s: couldn't parse Location header after 303", title)
	}
	q := u.Query()
	if c, ok := q["error"]; !ok {
		t.Fatalf("%s: not a valid oauth 2.0 error response: %s", title, u)
	} else if c[0] != code {
		t.Fatalf("%s: invalid error (expected %s, got %s)", title, code, c)
	}
	if d, ok := q["error_description"]; !ok {
		t.Fatalf("%s: not a valid oauth 2.0 error response: %s", title, u)
	} else if d[0] != description {
		t.Fatalf(
			"%s: invalid error_description (expected %s, got %s)", title,
			description, d,
		)
	}
}

func expectBadRequest(title string, t *testing.T, r *http.Response, xBody string) {
	if r.StatusCode != 400 {
		t.Fatalf("%s: Unexpected response (expected 400, got %s)", title, r.Status)
	}
	if xBody != "" {
		if body, err := ioutil.ReadAll(r.Body); err != nil {
			t.Fatal(err)
		} else if string(body) != xBody {
			t.Fatalf(
				"%s: Unexpected body (expected: %s, got: %s)", title, xBody, body,
			)
		}
	}
}
