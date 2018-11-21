package io.imulab.nix.client.metadata

import io.imulab.nix.support.OAuthEnum

enum class ResponseType (override val specValue: String): OAuthEnum {
    Code("code"),
    Token("token"),
    IdToken("id_token"),
    None("none")
}