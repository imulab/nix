package deprecated.oauth.session

import deprecated.oauth.token.TokenType
import java.time.LocalDateTime

/**
 * Represents the session data between OAuth2 requests.
 */
interface OAuthSession {

    /**
     * Expiry of a token of type [TokenType].
     */
    val expiry: MutableMap<TokenType, LocalDateTime>

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

    fun hasExpired(tokenType: TokenType): Boolean =
        expiry[tokenType]?.isAfter(LocalDateTime.now()) == true
}