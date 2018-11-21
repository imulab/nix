package io.imulab.nix.oauth.token

import io.imulab.nix.constant.Misc

class SignedToken(override val type: TokenType,
                  private val raw: String): Token {

    override val value: String
        get() = raw

    override val signature: String
        get() {
            val parts = raw.split(Misc.DOT)
            if (parts.size != 2)
                TODO("invalid token, malformed")
            return parts[1]
        }
}