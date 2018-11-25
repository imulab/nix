package deprecated.oauth.token.storage

import deprecated.oauth.request.OAuthRequest
import deprecated.oauth.token.Token


interface AuthorizeCodeStorage {

    /**
     * Stores authorization request for given authorize code.
     */
    suspend fun createAuthorizeCodeSession(code: Token, request: OAuthRequest)

    /**
     * Retrieves authorization request for given [code]. Implementations
     * should throw exception if the [code] has already been invalidated.
     */
    suspend fun getAuthorizeCodeSession(code: Token): OAuthRequest

    /**
     * Invalidates the stored session identified by [code]. It should be called when the [code] is used.
     */
    suspend fun invalidateAuthorizeCodeSession(code: Token)
}