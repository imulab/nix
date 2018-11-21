package io.imulab.nix.client.metadata

import io.imulab.nix.support.OAuthEnum

enum class AuthenticationMethod(override val specValue: String): OAuthEnum {
    ClientSecretJwt("client_secret_jwt"),
    ClientSecretBasic("client_secret_basic"),
    ClientSecretPost("client_secret_post"),
    PrivateKeyJwt("private_key_jwt"),
    None("none"),
    Unspecified("")
}