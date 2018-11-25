package deprecated.client.metadata

import deprecated.support.OAuthEnum

enum class ResponseType (override val specValue: String): OAuthEnum {
    Code("code"),
    Token("token"),
    IdToken("id_token"),
    None("none")
}