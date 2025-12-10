package oauth2server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type MockFlowStore struct {
	*InMemoryFlowStore
	StoreAuthCodeErr    error
	StoreAccessTokenErr error
}

func (m *MockFlowStore) StoreAuthCode(ctx context.Context, clientID string, code string, data AuthCodeData) error {
	if m.StoreAuthCodeErr != nil {
		return m.StoreAuthCodeErr
	}
	return m.InMemoryFlowStore.StoreAuthCode(ctx, clientID, code, data)
}

func (m *MockFlowStore) StoreAccessToken(ctx context.Context, clientID string, code, token string) error {
	if m.StoreAccessTokenErr != nil {
		return m.StoreAccessTokenErr
	}
	return m.InMemoryFlowStore.StoreAccessToken(ctx, clientID, code, token)
}

func TestAuthenticatedHandler(t *testing.T) {
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

	t.Run("MissingClientQuery", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authenticated", nil)
		w := httptest.NewRecorder()
		flow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "missing redirect_uri") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("InvalidBase64ClientQuery", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query=invalid-base64", nil)
		w := httptest.NewRecorder()
		flow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "failed to decode client_query") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("MissingRedirectURI", func(t *testing.T) {
		v := url.Values{}
		v.Set("client_id", "test-client")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		flow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "missing redirect_uri") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("InvalidRedirectURI", func(t *testing.T) {
		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", ":/invalid-uri") // Invalid URL
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		flow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "failed to parse redirect_uri") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("NewAccessTokenFuncError", func(t *testing.T) {
		fConfig := config
		fConfig.NewAccessTokenFunc = func(r *http.Request) (string, error) {
			return "", errors.New("token error")
		}
		fFlow := NewFlow(fConfig, store)

		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", "http://client.example.com/callback")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		fFlow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "failed to extract access token") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("NewAuthCodeFuncError", func(t *testing.T) {
		fConfig := config
		fConfig.NewAuthCodeFunc = func(r *http.Request) (string, error) {
			return "", errors.New("auth code error")
		}
		fFlow := NewFlow(fConfig, store)

		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", "http://client.example.com/callback")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		fFlow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
		if !strings.Contains(w.Body.String(), "failed to create auth code") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("MissingCodeChallenge", func(t *testing.T) {
		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", "http://client.example.com/callback")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		flow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "missing code_challenge") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("InvalidCodeChallengeMethod", func(t *testing.T) {
		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", "http://client.example.com/callback")
		v.Set("code_challenge", "challenge")
		v.Set("code_challenge_method", "plain")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		flow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "code_challenge_method must be S256") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("StoreAuthCodeError", func(t *testing.T) {
		mockStore := &MockFlowStore{
			InMemoryFlowStore: store,
			StoreAuthCodeErr:  errors.New("store auth code error"),
		}
		fFlow := NewFlow(config, mockStore)

		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", "http://client.example.com/callback")
		v.Set("code_challenge", "challenge")
		v.Set("code_challenge_method", "S256")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		fFlow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
		if !strings.Contains(w.Body.String(), "failed to store auth data") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("StoreAccessTokenError", func(t *testing.T) {
		mockStore := &MockFlowStore{
			InMemoryFlowStore:   store,
			StoreAccessTokenErr: errors.New("store access token error"),
		}
		fFlow := NewFlow(config, mockStore)

		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", "http://client.example.com/callback")
		v.Set("code_challenge", "challenge")
		v.Set("code_challenge_method", "S256")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		fFlow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
		if !strings.Contains(w.Body.String(), "failed to store access token") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("Success", func(t *testing.T) {
		v := url.Values{}
		v.Set("client_id", "test-client")
		v.Set("redirect_uri", "http://client.example.com/callback")
		v.Set("code_challenge", "challenge")
		v.Set("code_challenge_method", "S256")
		v.Set("state", "xyz")
		encoded := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		req := httptest.NewRequest(http.MethodGet, "/authenticated?client_query="+encoded, nil)
		w := httptest.NewRecorder()
		flow.AuthenticatedHandler(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected status %d, got %d", http.StatusFound, w.Code)
		}

		location := w.Header().Get("Location")
		parsedLocation, err := url.Parse(location)
		if err != nil {
			t.Fatalf("failed to parse location: %v", err)
		}

		if parsedLocation.Scheme != "http" || parsedLocation.Host != "client.example.com" || parsedLocation.Path != "/callback" {
			t.Errorf("unexpected redirect location: %s", location)
		}

		q := parsedLocation.Query()
		if q.Get("code") != "test-auth-code" {
			t.Errorf("expected code test-auth-code, got %s", q.Get("code"))
		}
		if q.Get("state") != "xyz" {
			t.Errorf("expected state xyz, got %s", q.Get("state"))
		}
	})
}
