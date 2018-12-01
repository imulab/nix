package io.imulab.nix.oauth.error

// unauthorized_client
// -------------------
// The client is not authorized to request an authorization
// code using this method.
// OR
// The client is not authorized to request an access token
// using this method.
// OR
// The authenticated client is not authorized to use this
// authorization grant type.
object UnauthorizedClient {
    private const val code = "unauthorized_client"
    private const val status = 400

    val forbiddenResponseType: (String) -> Throwable =
        { rt ->
            OAuthException(
                status,
                code,
                "Client is not unauthorized to use response_type <$rt>."
            )
        }

    val forbiddenGrantType: (String) -> Throwable =
        { gt ->
            OAuthException(
                status,
                code,
                "Client is not unauthorized to use grant_type <$gt>."
            )
        }
}