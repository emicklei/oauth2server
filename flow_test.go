package oauth2server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOAuth2FlowWithRecorder(t *testing.T) {
	store := NewInMemoryFlowStore()
	config := FlowConfig{
		NewClientCredentialsFunc: func() (string, string) {
			return "YOUR_CLIENT_ID", "YOUR_CLIENT_SECRET"
		},
		NewAccessTokenFunc: func() string {
			return "new-access-token"
		},
		NewAuthCodeFunc: func() string {
			return "new-auth-code"
		},
	}
	flow := NewFlow(config, store)

	// 1. Register a new client
	clientName := "test-client"
	form := url.Values{}
	form.Add("client_name", clientName)
	req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	flow.RegisterHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rr.Code)
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
