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

func TestOAuth2FlowWithRecorder(t *testing.T) {
	store := NewInMemoryFlowStore()
	config := FlowConfig{
		NewClientSecretFunc: func(r *http.Request) string {
			return "YOUR_CLIENT_SECRET"
		},
		NewAuthCodeFunc: func(r *http.Request) string {
			return "new-auth-code"
		},
		NewAccessTokenFunc: func(r *http.Request) (string, error) {
			return "access-token", nil
		},
	}
	flow := NewFlow(config, store)

	// 1. Register a new client
	clientName := "test-client"
	form := url.Values{}
	form.Add("client_name", clientName)
	form.Add("redirect_uris", "http://localhost:8080/callback")
	req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	flow.RegisterHandler(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d", rr.Code)
	}

	// 2. Authorize and get an authorization code
	authURL := "/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8080/callback&state=1234"
	form = url.Values{}
	form.Add("username", "user")
	form.Add("password", "pass")
	req, _ = http.NewRequest("POST", authURL, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	flow.AuthorizeHandler(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rr.Code)
	}
	redirectURL, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse redirect location: %v", err)
	}
	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatal("did not get authorization code")
	}

	// 3. Exchange authorization code for an access token
	form = url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	req, _ = http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	flow.TokenHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rr.Code)
	}
	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("could not decode token response: %v", err)
	}
	accessToken, ok := tokenResponse["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("did not get access token")
	}

	// 4. Access protected resource
	req, _ = http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr = httptest.NewRecorder()
	flow.ProtectedHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rr.Code)
	}
}
