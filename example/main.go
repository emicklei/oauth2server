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

	log.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
