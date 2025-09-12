package oauth2server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOauthServerMetadata(t *testing.T) {
	config := FlowConfig{
		AuthorizationBaseEndpoint: "http://localhost:8080",
		AuthorizePath:             "/oauth2/authorize",
		TokenPath:                 "/oauth2/token",
		RegisterPath:              "/oauth2/register",
		AuthorizationScopes:       []string{"scope1", "scope2"},
		// satisfy validation
		ResourceHandlerFunc:   func(w http.ResponseWriter, r *http.Request) {},
		NewClientSecretFunc:   func(r *http.Request) (string, error) { return "", nil },
		NewAuthCodeFunc:       func(r *http.Request) (string, error) { return "", nil },
		NewAccessTokenFunc:    func(r *http.Request) (string, error) { return "", nil },
		NewRefreshTokenFunc:   func(r *http.Request) (string, error) { return "", nil },
		LoginEndpoint:         "/login",
		ResourcePath:          "/protected",
		AuthenticatedPath:     "/authenticated",
		AccessTokenHeaderName: "X-Token",
	}
	f := NewFlow(config, NewInMemoryFlowStore())

	req, err := http.NewRequest("GET", OauthServerMetadataPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(f.OauthServerMetadata)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	var metadata OauthServerMetadata
	if err := json.NewDecoder(rr.Body).Decode(&metadata); err != nil {
		t.Fatalf("could not decode response body: %v", err)
	}

	if got, want := metadata.Issuer, f.config.AuthorizationBaseEndpoint; got != want {
		t.Errorf("issuer is wrong, got %q, want %q", got, want)
	}
	if got, want := metadata.AuthorizationEndpoint, "http://localhost:8080/oauth2/authorize"; got != want {
		t.Errorf("authorization_endpoint is wrong, got %q, want %q", got, want)
	}
	if got, want := metadata.TokenEndpoint, "http://localhost:8080/oauth2/token"; got != want {
		t.Errorf("token_endpoint is wrong, got %q, want %q", got, want)
	}
	if got, want := metadata.RegistrationEndpoint, "http://localhost:8080/oauth2/register"; got != want {
		t.Errorf("registration_endpoint is wrong, got %q, want %q", got, want)
	}
	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("unexpected number of scopes supported, got %d want 2", len(metadata.ScopesSupported))
	}
}
