package io.imulab.nix.oauth.token

import io.imulab.nix.constant.Misc

/**
 * Interface representing a token in the context of OAuth and Open ID Connect.
 */
interface Token {
    val type: TokenType
    val value: String
    val signature: String

    fun isEncrypted(): Boolean = false
}

/**
 * Represents a token in the format of <value.signature>.
 */
class SignedToken(override val type: TokenType, private val raw: String): Token {
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

/**
 * Represents a json web token.
 */
class JwtToken(override val type: TokenType, private val raw: String): Token {
    override val value: String
        get() = raw
    override val signature: String
        get() {
            val parts = raw.split(Misc.DOT)
            if (parts.size != 3)
                TODO("invalid token, malformed")
            return parts[2]
        }
}

/**
 * Represents a json web encryption token.
 */
class JweToken(override val type: TokenType, private val raw: String): Token {
    override val value: String
        get() = raw
    override val signature: String
        get() = ""
    override fun isEncrypted(): Boolean = true
}