package oauth2server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug})))
}

func TestOAuth2Flow(t *testing.T) {
	mux := new(http.ServeMux)
	local := httptest.NewServer(mux)
	defer local.Close()

	// simulate authentication
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		t.Log("logging in and", "redirect_uri", redirectURI)
		http.Redirect(w, r, redirectURI, http.StatusFound)
	})

	store := NewInMemoryFlowStore()
	config := FlowConfig{
		NewClientSecretFunc: func(r *http.Request) string {
			return "test-secret"
		},
		NewAuthCodeFunc: func(r *http.Request) string {
			return randSeq(32)
		},
		NewAccessTokenFunc: func(r *http.Request) (string, error) {
			return "test-access-token", nil
		},
		LoginEndpoint:             local.URL + "/login",
		AuthorizationBaseEndpoint: local.URL,
		ResourcePath:              "/test-protected",
		AuthorizePath:             "/test-authorize",
		TokenPath:                 "/test-token",
		AuthenticatedPath:         "/test-authenticated",
		RegisterPath:              "/test-register",
	}
	flow := NewFlow(config, store)
	flow.RegisterHandlers(mux)

	client := new(http.Client)

	// 1. Register client
	clientName := "test-client"
	callback := "http://localhost:8080/callback"
	form := url.Values{}
	form.Add("client_name", clientName)
	form.Add("redirect_uris", callback)

	req, _ := http.NewRequest("POST", local.URL+config.RegisterPath, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(req.URL, err)
	}
	if resp.StatusCode != 201 {
		t.Fatal(req.URL, resp.StatusCode)
	}
	registrations := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&registrations)

	clientID := registrations["client_id"]
	if clientID == nil {
		t.Fatal(registrations)
	}
	clientSecret := registrations["client_secret"]
	if clientSecret == nil {
		t.Fatal(registrations)
	}

	// 2. Authorize and redirect to Auth
	state := randSeq(4)
	query := url.Values{}
	query.Set("client_id", clientID.(string))
	query.Set("response_type", "code")
	query.Set("redirect_uri", callback)
	query.Set("state", state)
	req, _ = http.NewRequest("GET", local.URL+config.AuthorizePath+"?"+query.Encode(), nil)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(req.URL, err)
	}
	if resp.StatusCode != 201 {
		t.Fatal(req.URL, resp.StatusCode)
	}
}
