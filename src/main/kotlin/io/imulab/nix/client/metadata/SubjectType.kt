package io.imulab.nix.client.metadata

import io.imulab.nix.support.OAuthEnum

enum class SubjectType(override val specValue: String): OAuthEnum {
    Public("public"),
    Pairwise("pairwise"),
    Unspecified("")
}
