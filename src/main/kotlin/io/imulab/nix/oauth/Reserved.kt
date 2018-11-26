package io.imulab.nix.oauth

object Param {
    // (new to) client
    const val clientId = "client_id"
    const val clientSecret = "client_secret"

    // (new to) authorization request
    const val responseType = "response_type"
    const val redirectUri = "redirectUri"
    const val scope = "scope"
    const val state = "state"

    // (new to) authorization response
    const val code = "code"

    // (new to) access token request
    const val grantType = "grant_type"
    const val username = "username"
    const val password = "password"

    // (new to) access token response
    const val accessToken = "access_token"
    const val tokenType = "token_type"
    const val expiresIn = "expires_in"
    const val refreshToken = "refresh_token"

    // (new to) error
    const val error = "error"
    const val errorDescription = "error_description"
    const val errorUri = "error_uri"
}

object Header {
    const val authorization = "Authorization"
}

object ResponseType {
    const val code = "code"
    const val token = "token"

    enum class Value(val spec: String) {
        Code(code), Token(token)
    }
}

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

object ClientType {
    const val public = "public"
    const val confidential = "confidential"

    enum class Value(val spec: String) {
        Public(public), Confidential(confidential)
    }
}

object AuthenticationMethod {
    const val clientSecretBasic = "client_secret_basic"
    const val clientSecretPost = "client_secret_post"
}

const val colon = ":"
const val space = " "