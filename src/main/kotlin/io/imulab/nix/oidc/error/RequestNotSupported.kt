package io.imulab.nix.oidc.error

import io.imulab.nix.oauth.error.OAuthException

// request_not_supported
// ---------------------
// The OP does not support use of the request parameter defined in
// Section 6 (https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests).
object RequestNotSupported {
    private const val code = "request_not_supported"
    private const val status = 400

    val unsupported: (String) -> Throwable =
        { param ->
            OAuthException(
                status,
                code,
                "The value or use of request parameter <$param> is not supported."
            )
        }
}