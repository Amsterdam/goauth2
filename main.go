// Command authz runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amsterdam/authz/oauth2"
	log "github.com/sirupsen/logrus"
)

func main() {
	// Load and check configuration
	conf := conf()

	// Set log formatter
	if conf.LogJSON {
		log.SetFormatter(&log.JSONFormatter{})
	}

	// Get options
	opts := options(conf)

	// Create handler
	oauthHandler, err := oauth2.Handler(conf.BaseURL, conf.Accesstoken.JWKS, opts...)
	if err != nil {
		log.Fatal(err)
	}
	// ... wrap in middleware
	handler := &Handler{oauthHandler, conf}

	// Create server
	bindAddr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	server := &http.Server{Addr: bindAddr, Handler: handler}

	// Shut down server if signal is received
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
		<-signalChan
		server.Shutdown(context.Background())
		log.Infoln("Signal received, stopping service.")
	}()

	// Start the OAuth 2.0 server
	log.Printf("Starting service on %s.\n", bindAddr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Warnln("Error shutting down service: %v\n", err)
	} else {
		log.Println("Server stopped")
	}
}

// configuration returns the service configuration
func conf() *config {
	var configPath = flag.String("config", "", "Path to a configuration file.")
	flag.Parse()
	conf, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	// Check that base URL is set
	if conf.BaseURL == "" {
		log.Fatal("Must set base-url in config")
	}
	// Check that the JWKS is set
	if conf.Accesstoken.JWKS == "" {
		log.Fatal("Must set JSON Web Key Set (jwk-set) in config")
	}
	// Warn if profiler is enabled
	if conf.PprofEnabled {
		log.Warnln("Profiling should not be enbaled in production!")
	}
	return conf
}

func options(conf *config) []oauth2.Option {
	var options []oauth2.Option
	// IdP
	if (conf.IDP != idpConfig{}) {
		if idp, err := newDatapuntIDP(
			conf.IDP.BaseURL, conf.IDP.AccountsURL, []byte(conf.IDP.Secret), conf.IDP.APIKey,
		); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, oauth2.IDProvider(idp))
		}
	} else {
		log.Fatal("Must configure an IdP")
	}
	// Clients
	if len(conf.Clients) == 0 {
		log.Fatal("Must configure at least one registered client")
	}
	options = append(options, oauth2.Clients(conf.Clients))
	// Access token config
	if conf.Accesstoken.KID != "" {
		options = append(options, oauth2.JWKID(conf.Accesstoken.KID))
	}
	if conf.Accesstoken.Lifetime != 0 {
		options = append(
			options, oauth2.AccessTokenLifetime(conf.Accesstoken.Lifetime),
		)
	}
	if conf.Accesstoken.Issuer != "" {
		options = append(
			options, oauth2.AccessTokenIssuer(conf.Accesstoken.Issuer),
		)
	}
	// Authorization provider
	if (conf.Authz != authzConfig{}) {
		if authz, err := newDatapuntAuthz(&conf.Authz); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, oauth2.AuthzProvider(authz))
		}
	}
	// Storage provider
	if (conf.Redis != redisConfig{}) {
		engine := newRedisStorage(conf.Redis.Address, conf.Redis.Password)
		timeout := time.Duration(conf.AuthnTimeout) * time.Second
		options = append(options, oauth2.StateStorage(engine, timeout))
	}
	// Trace header
	if conf.TraceHeader != "" {
		options = append(options, oauth2.TraceHeader(conf.TraceHeader))
	}
	return options
}

// Handler is a wrapper that adds middleware for profiling and ping, and adds
// common headers to all responses.
type Handler struct {
	http.Handler
	Config *config
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/debug/pprof") && h.Config.PprofEnabled {
		h.handleProfiles(w, r)
	} else if r.URL.Path == "/ping" {
		h.servePing(w, r)
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		h.Handler.ServeHTTP(w, r)
	}
}

// handleProfiles determines which profile to return to the requester.
func (h *Handler) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/debug/pprof/cmdline":
		pprof.Cmdline(w, r)
	case "/debug/pprof/profile":
		pprof.Profile(w, r)
	case "/debug/pprof/symbol":
		pprof.Symbol(w, r)
	default:
		pprof.Index(w, r)
	}
}

// servePing returns a simple response to let the client know the server is running.
func (h *Handler) servePing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
