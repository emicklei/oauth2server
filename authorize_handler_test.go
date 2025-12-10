package oauth2server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizeHandler(t *testing.T) {
	store := NewInMemoryFlowStore()
	config := FlowConfig{
		AccessTokenExpiresIn:  3600,
		AccessTokenHeaderName: "X-Access-Token",
		ResourceHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
		},
		NewClientSecretFunc: func(r *http.Request) (string, error) {
			return "test-secret", nil
		},
		NewAuthCodeFunc: func(r *http.Request) (string, error) {
			return "test-auth-code", nil
		},
		NewAccessTokenFunc: func(r *http.Request) (string, error) {
			return "test-access-token", nil
		},
		NewRefreshTokenFunc: func(r *http.Request) (string, error) {
			return "test-refresh-token", nil
		},
		LoginEndpoint:             "http://login.example.com",
		AuthorizationBaseEndpoint: "http://auth.example.com",
		ResourcePath:              "/resource",
		AuthorizePath:             "/authorize",
		AuthenticatedPath:         "/authenticated",
		TokenPath:                 "/token",
		RegisterPath:              "/register",
		AuthorizationScopes:       []string{"read"},
	}

	// Register a test client
	client := Client{
		ID:           "test-client",
		Secret:       "test-secret",
		RedirectURIs: []string{"http://client.example.com/callback"},
	}
	store.RegisterClient(context.Background(), client)

	flow := NewFlow(config, store)

	t.Run("MissingClientID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		w := httptest.NewRecorder()
		flow.AuthorizeHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "client_id is required") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("InvalidClientID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=invalid", nil)
		w := httptest.NewRecorder()
		flow.AuthorizeHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "invalid client_id") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("MissingRedirectURI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=test-client", nil)
		w := httptest.NewRecorder()
		flow.AuthorizeHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "redirect_uri is required") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("InvalidRedirectURI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=test-client&redirect_uri=http://evil.com", nil)
		w := httptest.NewRecorder()
		flow.AuthorizeHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "invalid redirect_uri") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("Success", func(t *testing.T) {
		redirectURI := "http://client.example.com/callback"
		reqURL := "/authorize?client_id=test-client&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=xyz"
		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		w := httptest.NewRecorder()
		flow.AuthorizeHandler(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected status %d, got %d", http.StatusFound, w.Code)
		}

		location := w.Header().Get("Location")
		parsedLocation, err := url.Parse(location)
		if err != nil {
			t.Fatalf("failed to parse location header: %v", err)
		}

		if parsedLocation.Scheme != "http" || parsedLocation.Host != "login.example.com" {
			t.Errorf("unexpected redirect location base: %s", location)
		}

		targetRedirectURI := parsedLocation.Query().Get("redirect_uri")
		if targetRedirectURI == "" {
			t.Error("redirect_uri param missing in location")
		}

		// Verify the constructed redirect_uri
		// It should be AuthorizationBaseEndpoint + AuthenticatedPath + "?client_query=" + base64(...)

		expectedBase := config.AuthorizationBaseEndpoint + config.AuthenticatedPath
		if !strings.HasPrefix(targetRedirectURI, expectedBase) {
			t.Errorf("target redirect uri does not start with expected base. Got: %s, Expected prefix: %s", targetRedirectURI, expectedBase)
		}

		// Parse the client_query from the target redirect uri
		targetURL, _ := url.Parse(targetRedirectURI)
		clientQueryBase64 := targetURL.Query().Get("client_query")

		clientQueryBytes, err := base64.StdEncoding.DecodeString(clientQueryBase64)
		if err != nil {
			t.Fatalf("failed to decode client_query: %v", err)
		}

		clientQueryValues, err := url.ParseQuery(string(clientQueryBytes))
		if err != nil {
			t.Fatalf("failed to parse client_query values: %v", err)
		}

		if clientQueryValues.Get("client_id") != "test-client" {
			t.Errorf("expected client_id in client_query to be test-client, got %s", clientQueryValues.Get("client_id"))
		}
		if clientQueryValues.Get("redirect_uri") != redirectURI {
			t.Errorf("expected redirect_uri in client_query to be %s, got %s", redirectURI, clientQueryValues.Get("redirect_uri"))
		}
		if clientQueryValues.Get("state") != "xyz" {
			t.Errorf("expected state in client_query to be xyz, got %s", clientQueryValues.Get("state"))
		}
	})
}
