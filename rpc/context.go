// Quorum
package rpc

import (
	"context"
)

type securityContextKey string
type SecurityContext context.Context

const (
	HttpAuthorizationHeader              = "Authorization"
	HttpPrivateStateIdentifierHeader     = "Quorum-PSI"
	QueryPrivateStateIdentifierParamName = "PSI"
	EnvVarPrivateStateIdentifier         = "QUORUM_PSI"
	// this key is set into the secured context to indicate
	// the authorized private state being operated on for the request.
	// the value MUST BE OF TYPE types.PrivateStateIdentifier
	ctxPrivateStateIdentifier = securityContextKey("PRIVATE_STATE_IDENTIFIER")
	// this key is set into the request context to indicate
	// the private state being operated on for the request
	ctxRequestPrivateStateIdentifier = securityContextKey("REQUEST_PRIVATE_STATE_IDENTIFIER")
	// this key is exported for WS transport
	ctxCredentialsProvider = securityContextKey("CREDENTIALS_PROVIDER") // key to save reference to rpc.HttpCredentialsProviderFunc
	ctxPSIProvider         = securityContextKey("PSI_PROVIDER")         // key to save reference to rpc.PSIProviderFunc
	// keys used to save values in request context
	ctxAuthenticationError = securityContextKey("AUTHENTICATION_ERROR") // key to save error during authentication before processing the request body
)
