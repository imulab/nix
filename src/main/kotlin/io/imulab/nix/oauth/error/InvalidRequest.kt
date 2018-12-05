package io.imulab.nix.oauth.error

// invalid_request
// ---------------
// The request is missing a required parameter, includes an
// invalid parameter value, includes a parameter more than
// once, or is otherwise malformed.
object InvalidRequest {
    private const val code = "invalid_request"
    private const val status = 400

    val required: (String) -> Throwable =
        { param -> OAuthException(status, code, "Parameter $param is required.") }

    val invalid: (String) -> Throwable =
        { param -> OAuthException(status, code, "Value for parameter $param is invalid.") }

    val duplicate: (String) -> Throwable =
        { param ->
            OAuthException(
                status,
                code,
                "Parameter $param is duplicated in the request."
            )
        }

    val undetermined: (String) -> Throwable =
        { param ->
            OAuthException(
                status,
                code,
                "Value for parameter $param cannot be determined."
            )
        }

    val unmet: (String) -> Throwable =
        { feature ->
            OAuthException(
                status,
                code,
                "Request must have the following feature: $feature."
            )
        }
}