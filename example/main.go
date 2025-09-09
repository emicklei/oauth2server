package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/emicklei/oauth2server"
	"github.com/google/uuid"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OAuth2 Server")
	})
	config := oauth2server.FlowConfig{
		NewClientSecretFunc: func(r *http.Request) string {
			return uuid.NewString()
		},
		NewAccessTokenFunc: func(r *http.Request) string {
			return uuid.NewString()
		},
		ResourceHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Protected Resource Accessed")
		},
		AuthorizePath:             "/oauth2/authorize",
		AuthenticatedPath:         "/oauth2/authenticated",
		TokenPath:                 "/oauth2/token",
		RegisterPath:              "/oauth2/register",
		AuthorizationScopes:       []string{"all", "openid", "profile", "email"},
		LoginEndpoint:             "http://localhost:8080/login",
		ResourcePath:              "/protected",
		AuthorizationBaseEndpoint: "http://localhost:8080",
	}
	store := oauth2server.NewInMemoryFlowStore()

	flow := oauth2server.NewFlow(config, store)

	http.HandleFunc(oauth2server.OauthServerMetadataPath, flow.OauthServerMetadata)
	http.HandleFunc(config.AuthorizePath, flow.AuthorizeHandler)
	http.HandleFunc(config.AuthenticatedPath, flow.AuthenticatedHandler)
	http.HandleFunc(config.TokenPath, flow.TokenHandler)
	http.HandleFunc(config.ResourcePath, flow.ProtectedHandler)
	http.HandleFunc(config.RegisterPath, flow.RegisterHandler)

	log.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
