package io.imulab.nix.oauth

interface ReservedWordValidator {
    fun validate(value: String): String
}

object OAuthResponseTypeValidator : ReservedWordValidator {
    override fun validate(value: String): String {
        return when (value) {
            ResponseType.code, ResponseType.token -> value
            else -> throw UnsupportedResponseType.unsupported(value)
        }
    }
}

object OAuthGrantTypeValidator : ReservedWordValidator {
    override fun validate(value: String): String {
        return when (value) {
            GrantType.authorizationCode,
            GrantType.implicit,
            GrantType.password,
            GrantType.clientCredentials,
            GrantType.refreshToken -> value
            else -> throw UnsupportedGrantType.unsupported(value)
        }
    }
}

object ClientTypeValidator : ReservedWordValidator {
    override fun validate(value: String): String {
        return when (value) {
            ClientType.public, ClientType.confidential -> value
            else -> throw ServerError.internal("Illegal client type <$value>.")
        }
    }
}

object OAuthClientAuthenticationMethodValidator : ReservedWordValidator {
    override fun validate(value: String): String {
        return when (value) {
            AuthenticationMethod.clientSecretBasic,
            AuthenticationMethod.clientSecretPost -> value
            else -> throw ServerError.internal("Illegal client authentication method named <$value>.")
        }
    }
}