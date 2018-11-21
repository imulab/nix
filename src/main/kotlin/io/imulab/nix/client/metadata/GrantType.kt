package io.imulab.nix.client.metadata

import io.imulab.nix.support.OAuthEnum

enum class GrantType(override val specValue: String): OAuthEnum {
    AuthorizationCode("authorization_code"),
    Implicit("implicit"),
    Password("password"),
    ClientCredentials("client_credentials"),
    RefreshToken("refresh_token")
}