package oauth2server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegisterHandler(t *testing.T) {
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
		LoginEndpoint:             "/login",
		AuthorizationBaseEndpoint: "http://localhost",
		ResourcePath:              "/resource",
		AuthorizePath:             "/authorize",
		AuthenticatedPath:         "/authenticated",
		TokenPath:                 "/token",
		RegisterPath:              "/register",
		AuthorizationScopes:       []string{"read"},
	}
	flow := NewFlow(config, store)

	t.Run("MethodNotAllowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/register", nil)
		w := httptest.NewRecorder()
		flow.RegisterHandler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})

	t.Run("SuccessJSON", func(t *testing.T) {
		regReq := RegistrationRequest{
			ClientName:   "test-client",
			RedirectURIs: []string{"http://localhost/callback"},
		}
		body, _ := json.Marshal(regReq)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		flow.RegisterHandler(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
		}

		var resp RegisterResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.ClientID == "" {
			t.Error("expected client_id to be set")
		}
		if resp.ClientSecret != "test-secret" {
			t.Errorf("expected client_secret 'test-secret', got '%s'", resp.ClientSecret)
		}
	})

	t.Run("SuccessForm", func(t *testing.T) {
		form := url.Values{}
		form.Set("client_name", "test-client-form")
		form.Add("redirect_uris", "http://localhost/callback")

		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		flow.RegisterHandler(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
		}

		var resp RegisterResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.ClientID == "" {
			t.Error("expected client_id to be set")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("{invalid-json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		flow.RegisterHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("MissingFields", func(t *testing.T) {
		regReq := RegistrationRequest{
			ClientName: "test-client",
			// Missing RedirectURIs
		}
		body, _ := json.Marshal(regReq)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		flow.RegisterHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}
