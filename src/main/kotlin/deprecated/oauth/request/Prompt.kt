package deprecated.oauth.request

import deprecated.support.OAuthEnum

enum class Prompt(override val specValue: String): OAuthEnum {
    None("none"),
    Login("login"),
    Consent("consent"),
    SelectAccount("select_account")
}