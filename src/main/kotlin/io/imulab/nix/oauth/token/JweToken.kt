package io.imulab.nix.oauth.token

class JweToken(override val type: TokenType,
               private val raw: String): EncryptedToken {

    override val value: String
        get() = raw
}