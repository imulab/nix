package deprecated.oauth.token

import deprecated.support.OAuthEnum

enum class TokenType(override val specValue: String): OAuthEnum {
    AuthorizeCode("authorize_code"),
    AccessToken("access_token"),
    RefreshToken("refresh_token"),
    IdToken("id_token"),
    Unspecified(""),
}