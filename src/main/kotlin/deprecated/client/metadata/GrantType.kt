package deprecated.client.metadata

import deprecated.support.OAuthEnum

enum class GrantType(override val specValue: String): OAuthEnum {
    AuthorizationCode("authorization_code"),
    Implicit("implicit"),
    Password("password"),
    ClientCredentials("client_credentials"),
    RefreshToken("refresh_token")
}