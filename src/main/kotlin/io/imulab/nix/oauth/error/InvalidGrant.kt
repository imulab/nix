package io.imulab.nix.oauth.error

// invalid_grant
// -------------
// The provided authorization grant (e.g., authorization
// code, resource owner credentials) or refresh token is
// invalid, expired, revoked, does not match the redirection
// URI used in the authorization request, or was issued to
// another client.
object InvalidGrant {
    private const val code = "invalid_grant"
    private const val status = 400

    val invalid: () -> Throwable =
        { OAuthException(status, code, "Presented grant is invalid.") }

    val expired: () -> Throwable =
        { OAuthException(status, code, "Presented grant has expired.") }

    val revoked: () -> Throwable =
        { OAuthException(status, code, "Presented grant has been revoked.") }

    val impersonate: () -> Throwable =
        { OAuthException(status, code, "Presented grant was not issued to client.") }
}