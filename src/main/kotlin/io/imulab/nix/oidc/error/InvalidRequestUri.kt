package io.imulab.nix.oidc.error

import io.imulab.nix.oauth.error.OAuthException

// invalid_request_uri
// -------------------
// The request_uri in the Authorization Request returns an error or
// contains invalid data.
object InvalidRequestUri {
    private const val code = "invalid_request_uri"
    private const val status = 400

    val none200: (Int) -> Throwable =
        { i ->
            OAuthException(
                status,
                code,
                "Request URI returned invalid response status ($i)."
            )
        }

    val invalid: () -> Throwable =
        { OAuthException(status, code, "Request URI returned invalid data.") }

    val badHash: () -> Throwable =
        { OAuthException(status, code, "Request URI data does not match its hash.") }

    val rouge: () -> Throwable =
        { OAuthException(status, code, "Request URI was not pre-registered with client.") }

    val tooLong: () -> Throwable =
        { OAuthException(status, code, "Request URI must not exceed 512 ASCII characters.") }
}