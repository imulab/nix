package io.imulab.nix.oidc.error

import io.imulab.nix.oauth.error.OAuthException

// invalid_request_object
// ----------------------
// The request parameter contains an invalid Request Object.
object InvalidRequestObject {
    private const val code = "invalid_request_object"
    private const val status = 400

    val invalid: () -> Throwable =
        { OAuthException(status, code, "Request object contained invalid data.") }
}