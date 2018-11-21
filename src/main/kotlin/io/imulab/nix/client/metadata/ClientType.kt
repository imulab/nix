package io.imulab.nix.client.metadata

import io.imulab.nix.support.OAuthEnum

enum class ClientType(override val specValue: String): OAuthEnum {
    CONFIDENTIAL("confidential"),
    PUBLIC("public");
}