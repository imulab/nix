package io.imulab.nix.oauth

interface ReservedWordValidator {
    fun validate(value: String): String
}

class OAuthResponseTypeValidator: ReservedWordValidator {
    override fun validate(value: String): String {
        return when (value) {
            ResponseType.code, ResponseType.token -> value
            else -> throw UnsupportedResponseType.unsupported(value)
        }
    }
}

class OAuthGrantTypeValidator: ReservedWordValidator {
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