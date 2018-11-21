package io.imulab.nix.oauth.token

interface Token {

    val type: TokenType

    val value: String

    val signature: String
}