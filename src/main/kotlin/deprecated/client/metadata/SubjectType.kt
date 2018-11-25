package deprecated.client.metadata

import deprecated.support.OAuthEnum

enum class SubjectType(override val specValue: String): OAuthEnum {
    Public("public"),
    Pairwise("pairwise"),
    Unspecified("")
}
