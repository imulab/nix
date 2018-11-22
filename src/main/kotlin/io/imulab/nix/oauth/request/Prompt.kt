package io.imulab.nix.oauth.request

import io.imulab.nix.support.OAuthEnum

enum class Prompt(override val specValue: String): OAuthEnum {
    None("none"),
    Login("login"),
    Consent("consent"),
    SelectAccount("select_account")
}