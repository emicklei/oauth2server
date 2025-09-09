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
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == "time" || a.Key == "level" {
			return slog.Attr{}
		}
		return a
	}})))
}

func TestOAuth2Flow(t *testing.T) {
	mux := new(http.ServeMux)
	local := httptest.NewServer(mux)
	defer local.Close()

	// simulate authentication
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		t.Log("logging in and", "redirect_uri:", redirectURI)
		r.AddCookie(&http.Cookie{Value: "test-cookie"})
		http.Redirect(w, r, redirectURI, http.StatusFound)
	})

	// simulate callback handling
	var code string
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		t.Log("called back", r.URL.Query())
		code = r.URL.Query().Get("code")
	})
	callback := local.URL + "/callback"

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
	if resp.StatusCode != 200 {
		t.Fatal(req.URL, resp.StatusCode)
	}

	// 3. Get Token

	// client_id=9a6a1dbe-546f-4983-96b0-23b267aaba76
	// &grant_type=authorization_code
	// &code=1e6b0a73-06c0-4622-bc6a-d6929e70efe1
	// &redirect_uri=http%3A%2F%2F127.0.0.1%3A33418
	// &code_verifier=9122e976a511934fb8918c766d2e9e34ad5a75e89d0859ff292dfcb1a92160e3
	// &client_secret=a021fce1-ebd0-4862-a8c1-ded798adbaae"

	form = url.Values{}
	form.Set("client_id", clientID.(string))
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callback)
	form.Set("code_verifier", "9122e976a511934fb8918c766d2e9e34ad5a75e89d0859ff292dfcb1a92160e3") // TODO how to compute this
	form.Set("client_secret", clientSecret.(string))

	req, _ = http.NewRequest("POST", local.URL+config.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(req.URL, err)
	}
	if resp.StatusCode != 200 {
		t.Fatal(req.URL, resp.StatusCode)
	}

}
