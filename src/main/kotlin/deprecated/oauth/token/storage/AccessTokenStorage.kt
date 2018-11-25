package deprecated.oauth.token.storage

import deprecated.oauth.request.OAuthRequest
import deprecated.oauth.token.Token

interface AccessTokenStorage {

    /**
     * Stores access request for the given access [token].
     */
    suspend fun createAccessTokenSession(token: Token, request: OAuthRequest)

    /**
     * Retrieves the request associated with the access [token].
     */
    suspend fun getAccessTokenSession(token: Token): OAuthRequest

    /**
     * Removes information related to the access [token].
     */
    suspend fun deleteAccessTokenSession(token: Token)
}