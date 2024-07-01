package oauth1

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type ServeMuxConfig struct {
	Config
	LoginPath    string
	CallbackPath string
}

func (a *ServeMuxConfig) setDefaults() {
	if a.LoginPath == "" {
		a.LoginPath = "/login"
	}
	if a.CallbackPath == "" {
		a.CallbackPath = "/callback"
	}
}

type ServeMux struct {
	*http.ServeMux
	*ServeMuxConfig
	requestToken  string
	requestSecret string
	token         *Token
	gotTokenAt    time.Time

	callbackMut *sync.Mutex
	callbackChs []chan bool
}

// NewServeMux creates a new HTTP serve mux with pre-configured login and callback endpoints for OAuth1 application.
func NewServeMux(config *ServeMuxConfig) *ServeMux {
	config.setDefaults()
	server := &ServeMux{
		ServeMux:       http.NewServeMux(),
		ServeMuxConfig: config,
		callbackMut:    &sync.Mutex{},
		callbackChs:    []chan bool{},
	}
	server.HandleFunc(config.LoginPath, server.login)
	server.HandleFunc(config.CallbackPath, server.callback)
	return server
}

func (s *ServeMux) login(w http.ResponseWriter, r *http.Request) {
	url, err := s.authorize()
	if err != nil {
		w.WriteHeader(500)
		fmt.Printf("failed to authorize: %e\n", err)
		return
	}
	http.Redirect(w, r, url.String(), http.StatusFound)
}

func (s *ServeMux) callback(w http.ResponseWriter, r *http.Request) {
	// parse the raw query from the URL into req.Form
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(500)
		fmt.Printf("failed to parse form: %e\n", err)
		return
	}
	requestToken := r.Form.Get(oauthTokenParam)
	if requestToken == "" {
		requestToken = s.requestToken
	}
	verifier := r.Form.Get(oauthVerifierParam)

	if requestToken == "" || verifier == "" {
		w.WriteHeader(400)
		return
	}

	accessToken, accessSecret, err := s.AccessToken(requestToken, s.requestSecret, verifier)
	if err != nil {
		w.WriteHeader(500)
		fmt.Printf("failed to get access token: %e\n", err)
		return
	}
	s.token = NewToken(accessToken, accessSecret)
	s.gotTokenAt = time.Now()

	s.callbackMut.Lock()
	for _, ch := range s.callbackChs {
		ch <- true
	}
	s.callbackChs = []chan bool{}
	s.callbackMut.Unlock()
}

func (s *ServeMux) authorize() (*url.URL, error) {
	requestToken, requestSecret, err := s.RequestToken()
	if err != nil {
		return nil, err
	}
	s.requestToken = requestToken
	s.requestSecret = requestSecret
	return s.AuthorizationURL(requestToken)
}

// Token returns the last access token obtained by the serve mux.
func (a *ServeMux) Token() (*Token, error) {
	return a.token, nil
}

// Callback returns a channel that written to when the callback route is successfully invoked.
func (s *ServeMux) Callback() <-chan bool {
	s.callbackMut.Lock()
	ch := make(chan bool)
	s.callbackChs = append(s.callbackChs, ch)
	s.callbackMut.Unlock()
	return ch
}
