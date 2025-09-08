# OAuth2 Server

This is a simple OAuth2 server implementation in Go.

## Endpoints

### Authorization

- **URL:** `/oauth2/authorize`
- **Method:** `GET`, `POST`
- **Purpose:** This endpoint starts the OAuth2 flow. It displays a login page for the user to authenticate and grant consent. Upon successful authentication, it redirects the user back to the client application with an authorization code.

### Token

- **URL:** `/oauth2/token`
- **Method:** `POST`
- **Purpose:** This endpoint exchanges an authorization code for an access token.

### Protected Resource

- **URL:** `/protected`
- **Method:** `GET`
- **Purpose:** This is an example of a protected resource that requires a valid access token to be accessed. The access token must be included in the `Authorization` header as a Bearer token.

### Dynamic Client Registration

- **URL:** `/oauth2/register`
- **Method:** `POST`
- **Purpose:** This endpoint allows new clients to register with the server. It accepts a `client_name` parameter and returns a new `client_id` and `client_secret`.


## Features

- Zero dependencies
- OAuth 2.0 Authorization Server Metadata.
- Dynamic Client Registration

