package io.imulab.nix.oauth.error

// invalid_client
// --------------
// Client authentication failed (e.g., unknown client, no
// client authentication included, or unsupported
// authentication method).  The authorization server MAY
// return an HTTP 401 (Unauthorized) status code to indicate
// which HTTP authentication schemes are supported.  If the
// client attempted to authenticate via the "Authorization"
// request header field, the authorization server MUST
// respond with an HTTP 401 (Unauthorized) status code and
// include the "WWW-Authenticate" response header field
// matching the authentication scheme used by the client.
object InvalidClient {
    private const val code = "invalid_client"
    private const val status = 401

    val unknown: () -> Throwable =
        { OAuthException(status, code, "Client is unknown") }

    val authenticationRequired: () -> Throwable =
        { OAuthException(status, code, "Client credentials are required for this operation") }

    val authenticationFailed: () -> Throwable =
        { OAuthException(status, code, "Client failed authentication.") }

    val authenticationFailedWithReason: (String) -> Throwable =
        { reason ->
            OAuthException(
                status,
                code,
                "Client failed authentication due to $reason."
            )
        }

    val unauthorized: (String) -> Throwable = { scheme ->
        OAuthException(
            status, code, "Client failed authentication.", mapOf(
                "WWW-Authenticate" to scheme
            )
        )
    }
}