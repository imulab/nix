package io.imulab.nix.oauth.session

import io.imulab.nix.oauth.token.TokenType
import java.time.LocalDateTime

/**
 * Represents the session data between OAuth2 requests.
 */
interface OAuthSession {

    /**
     * Expiry of a token of type [TokenType].
     */
    val expiry: Map<TokenType, LocalDateTime>

    /**
     * Username of the session owner.
     */
    val username: String

    /**
     * Subject of the session owner
     */
    val subject: String

    /**
     * Returns a new identical session.
     */
    fun clone(): OAuthSession
}