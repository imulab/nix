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
 * Represents a token with signature.
 */
data class SignedToken(override val type: TokenType,
                       override val value: String,
                       override val signature: String): Token {
    override fun toString(): String = value + Misc.DOT + signature
}

/**
 * Represents a json web token.
 */
data class JwtToken(override val type: TokenType, private val raw: String): Token {
    override val value: String
        get() = raw
    override val signature: String
        get() {
            val parts = raw.split(Misc.DOT)
            if (parts.size != 3)
                TODO("invalid token, malformed")
            return parts[2]
        }

    override fun toString(): String = raw
}

/**
 * Represents a json web encryption token.
 */
data class JweToken(override val type: TokenType, private val raw: String): Token {
    override val value: String
        get() = raw
    override val signature: String
        get() = ""
    override fun isEncrypted(): Boolean = true

    override fun toString(): String = raw
}