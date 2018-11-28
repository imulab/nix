package io.imulab.nix.oauth

// invalid_request
// ---------------
// The request is missing a required parameter, includes an
// invalid parameter value, includes a parameter more than
// once, or is otherwise malformed.
object InvalidRequest {
    private const val code = "invalid_request"
    private const val status = 400

    val required: (String) -> Throwable =
        { param -> OAuthException(status, code, "Parameter <$param> is required.") }

    val invalid: (String) -> Throwable =
        { param -> OAuthException(status, code, "Value for parameter <$param> is invalid.") }

    val duplicate: (String) -> Throwable =
        { param -> OAuthException(status, code, "Parameter <$param> is duplicated in the request.") }

    val indetermined: (String) -> Throwable =
        { param -> OAuthException(status, code, "Value for parameter <$param> cannot be determined.") }

    val unmet: (String) -> Throwable =
        { feature -> OAuthException(status, code, "Request must have the following feature: $feature.") }
}

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
        { rt -> OAuthException(status, code, "Client is not unauthorized to use response_type <$rt>.") }

    val forbiddenGrantType: (String) -> Throwable =
        { gt -> OAuthException(status, code, "Client is not unauthorized to use grant_type <$gt>.") }
}

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
        { reason -> OAuthException(status, code, "Client failed authentication due to $reason.") }

    val unauthorized: (String) -> Throwable = { scheme ->
        OAuthException(
            status, code, "Client failed authentication.", mapOf(
                "WWW-Authenticate" to scheme
            )
        )
    }
}


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

// access_denied
// -------------
// The resource owner or authorization server denied the
// request.
object AccessDenied {
    private const val code = "access_denied"
    private const val status = 403

    val byOwner: () -> Throwable =
        { OAuthException(status, code, "Resource owner denied the request.") }

    val byServer: (String) -> Throwable =
        { reason -> OAuthException(status, code, "Resource server denied the request. $reason".trim()) }
}

// unsupported_response_type
// -------------------------
// The authorization server does not support obtaining an
// authorization code or access token using this method.
object UnsupportedResponseType {
    private const val code = "unsupported_response_type"
    private const val status = 400

    val unsupported: (String) -> Throwable =
        { rt -> throw OAuthException(status, code, "Use of response_type <$rt> is unsupported by this server.") }
}

// unsupported_grant_type
// ----------------------
// The authorization grant type is not supported by the
// authorization server.
object UnsupportedGrantType {
    private const val code = "unsupported_grant_type"
    private const val status = 400

    val unsupported: (String) -> Throwable =
        { gt -> throw OAuthException(status, code, "Use of grant_type <$gt> is unsupported by this server.") }
}

// invalid_scope
// -------------
// The requested scope is invalid, unknown, malformed, or
// exceeds the scope granted by the resource owner.
object InvalidScope {
    private const val code = "invalid_scope"
    private const val status = 400

    val invalid: (String) -> Throwable =
        { s -> throw OAuthException(status, code, "Scope <$s> is invalid.") }

    val unknown: (String) -> Throwable =
        { s -> throw OAuthException(status, code, "Scope <$s> is unknown.") }

    val malformed: (String) -> Throwable =
        { s -> throw OAuthException(status, code, "Scope <$s> is malformed.") }

    val notGranted: (String) -> Throwable =
        { s -> throw OAuthException(status, code, "Scope <$s> was not granted to client.") }
}

// server_error
object ServerError {
    const val code = "server_error"
    private const val status = 500

    val wrapped: (Throwable) -> Throwable =
        { t -> throw OAuthException(status, code, t.message ?: t.javaClass.name) }

    val internal: (String) -> Throwable =
        { m -> throw OAuthException(status, code, m) }
}

// temporarily_unavailable

class OAuthException(
    override val status: Int,
    val error: String,
    private val description: String,
    override val headers: Map<String, String> = emptyMap()
) : RuntimeException("$error: $description"), OAuthResponse {

    override val data: Map<String, String>
        get() = mapOf(
            Param.error to error,
            Param.errorDescription to description
        )
}