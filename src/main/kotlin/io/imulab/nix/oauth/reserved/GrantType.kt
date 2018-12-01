package io.imulab.nix.oauth.reserved

object GrantType {
    const val authorizationCode = "authorization_code"
    const val implicit = "implicit"
    const val password = "password"
    const val clientCredentials = "client_credentials"
    const val refreshToken = "refresh_token"

    enum class Value(val spec: String) {
        AuthCode(authorizationCode),
        Implicit(implicit),
        Password(password),
        ClientCredentials(clientCredentials),
        RefreshToken(refreshToken)
    }
}