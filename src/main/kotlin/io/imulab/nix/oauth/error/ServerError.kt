package io.imulab.nix.oauth.error

// server_error
object ServerError {
    const val code = "server_error"
    private const val status = 500

    val wrapped: (Throwable) -> Throwable =
        { t -> throw OAuthException(status, code, t.message ?: t.javaClass.name) }

    val internal: (String) -> Throwable =
        { m -> throw OAuthException(status, code, m) }
}