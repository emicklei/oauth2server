package oauth2server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockStore wraps InMemoryFlowStore to mock VerifyAccessToken
type mockStore struct {
	*InMemoryFlowStore
	verifyTokenFunc func(ctx context.Context, token string) (bool, error)
}

func (m *mockStore) VerifyAccessToken(ctx context.Context, token string) (bool, error) {
	if m.verifyTokenFunc != nil {
		return m.verifyTokenFunc(ctx, token)
	}
	return m.InMemoryFlowStore.VerifyAccessToken(ctx, token)
}

func TestProtectedHandler(t *testing.T) {
	resourceCalled := false
	var capturedRequest *http.Request

	// Define a base config
	baseConfig := FlowConfig{
		AccessTokenHeaderName: "X-Access-Token",
	}

	tests := []struct {
		name           string
		config         FlowConfig
		store          FlowStateStore
		authHeader     string
		expectedStatus int
		expectResource bool
	}{
		{
			name:   "Success",
			config: baseConfig,
			store: &mockStore{
				InMemoryFlowStore: NewInMemoryFlowStore(),
				verifyTokenFunc: func(ctx context.Context, token string) (bool, error) {
					if token == "valid-token" {
						return true, nil
					}
					return false, nil
				},
			},
			authHeader:     "Bearer valid-token",
			expectedStatus: http.StatusOK,
			expectResource: true,
		},
		{
			name:           "Missing Authorization Header",
			config:         baseConfig,
			store:          NewInMemoryFlowStore(),
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectResource: false,
		},
		{
			name:           "Invalid Authorization Header Format - No Bearer",
			config:         baseConfig,
			store:          NewInMemoryFlowStore(),
			authHeader:     "Basic user:pass",
			expectedStatus: http.StatusBadRequest,
			expectResource: false,
		},
		{
			name:           "Invalid Authorization Header Format - Wrong parts",
			config:         baseConfig,
			store:          NewInMemoryFlowStore(),
			authHeader:     "Bearer",
			expectedStatus: http.StatusBadRequest,
			expectResource: false,
		},
		{
			name:   "Invalid Access Token",
			config: baseConfig,
			store: &mockStore{
				InMemoryFlowStore: NewInMemoryFlowStore(),
				verifyTokenFunc: func(ctx context.Context, token string) (bool, error) {
					return false, nil
				},
			},
			authHeader:     "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
			expectResource: false,
		},
		{
			name:   "Store Error",
			config: baseConfig,
			store: &mockStore{
				InMemoryFlowStore: NewInMemoryFlowStore(),
				verifyTokenFunc: func(ctx context.Context, token string) (bool, error) {
					return false, errors.New("db error")
				},
			},
			authHeader:     "Bearer token",
			expectedStatus: http.StatusInternalServerError,
			expectResource: false,
		},
		{
			name: "No Resource Handler",
			config: FlowConfig{
				AccessTokenHeaderName: "X-Access-Token",
				ResourceHandlerFunc:   nil, // Explicitly nil
			},
			store:          NewInMemoryFlowStore(),
			authHeader:     "Bearer token",
			expectedStatus: http.StatusOK, // Returns without error, but doesn't write anything
			expectResource: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset state
			resourceCalled = false
			capturedRequest = nil

			// Copy config to avoid modifying baseConfig for subsequent tests
			cfg := tt.config
			// Setup resource handler if config expects one (i.e. not explicitly nil in test case)
			if cfg.ResourceHandlerFunc == nil && tt.name != "No Resource Handler" {
				cfg.ResourceHandlerFunc = func(w http.ResponseWriter, r *http.Request) {
					resourceCalled = true
					capturedRequest = r
					w.WriteHeader(http.StatusOK)
				}
			}

			f := &Flow{
				config: cfg,
				store:  tt.store,
			}

			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			f.ProtectedHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectResource != resourceCalled {
				t.Errorf("expected resource called %v, got %v", tt.expectResource, resourceCalled)
			}

			if tt.expectResource && capturedRequest != nil {
				// Check if access token header was set
				// Extract token from auth header
				token := "valid-token" // Hardcoded for the success case
				gotToken := capturedRequest.Header.Get(cfg.AccessTokenHeaderName)
				if gotToken != token {
					t.Errorf("expected token header %s, got %s", token, gotToken)
				}
			}
		})
	}
}
