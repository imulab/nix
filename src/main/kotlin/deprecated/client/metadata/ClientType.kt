package deprecated.client.metadata

import deprecated.support.OAuthEnum

enum class ClientType(override val specValue: String): OAuthEnum {
    CONFIDENTIAL("confidential"),
    PUBLIC("public");
}