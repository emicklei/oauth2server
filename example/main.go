package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/emicklei/oauth2server"
	"github.com/google/uuid"
)

func main() {
	config := oauth2server.FlowConfig{
		ResourceHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Protected Resource Accessed")
		},
		NewClientSecretFunc: func(r *http.Request) string {
			return uuid.NewString()
		},
		NewAccessTokenFunc: func(r *http.Request) (string, error) {
			return uuid.NewString(), nil
		},
		NewRefreshTokenFunc: func(r *http.Request) (string, error) {
			return uuid.NewString(), nil
		},
		RegisterPath:              "/oauth2/register",
		AuthorizePath:             "/oauth2/authorize",
		AuthenticatedPath:         "/oauth2/authenticated",
		TokenPath:                 "/oauth2/token",
		AuthorizationScopes:       []string{"all", "openid", "profile", "email"},
		LoginEndpoint:             "http://localhost:8080/login",
		ResourcePath:              "/protected",
		AuthorizationBaseEndpoint: "http://localhost:8080",
	}
	store := oauth2server.NewInMemoryFlowStore()

	flow := oauth2server.NewFlow(config, store)
	flow.RegisterHandlers(http.DefaultServeMux)

	// simple login form
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// In a real application, you would validate the username and password.
			// For this example, we'll just redirect back to the authenticated endpoint.
			redirectURI := r.URL.Query().Get("redirect_uri")
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}
		fmt.Fprintf(w, `
			<h1>Login</h1>
			<form method="post">
				<label for="username">Username:</label><br>
				<input type="text" id="username" name="username"><br>
				<label for="password">Password:</label><br>
				<input type="password" id="password" name="password"><br><br>
				<input type="submit" value="Submit">
			</form>
		`)
	})

	log.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
