package io.imulab.nix.oauth.token

import io.imulab.nix.support.OAuthEnum

enum class TokenType(override val specValue: String): OAuthEnum {
    AuthorizeCode("authorize_code"),
    AccessToken("access_token"),
    RefreshToken("refresh_token"),
    IdToken("id_token"),
    Unspecified(""),
}