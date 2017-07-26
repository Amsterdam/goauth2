package service

import (
	"net/http"

	"github.com/bmizerany/pat"
)

// methodHandler maps HTTP verbs to handler functions
type methodHandler map[string]func(http.ResponseWriter, *http.Request)

// Resource specifies how to handle a HTTP verb for a given endpoint.
type Resource struct {
	Name     string
	Pattern  string
	Handlers methodHandler
}

// Handler represents an HTTP request handler.
type Handler struct {
	mux *pat.PatternServeMux
}

// NewHandler returns a new instance of handler with routes.
func NewHandler() *Handler {
	h := &Handler{
		mux: pat.New(),
	}
	return h
}

// AddResources adds resources to the request handler.
func (h *Handler) addResources(resources ...Resource) {
	for _, r := range resources {
		for method, handlerFunc := range r.Handlers {
			var handler http.Handler
			handler = http.HandlerFunc(handlerFunc)
			h.mux.Add(method, r.Pattern, handler)
		}
	}
}

// ServeHTTP responds to HTTP request to the handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}