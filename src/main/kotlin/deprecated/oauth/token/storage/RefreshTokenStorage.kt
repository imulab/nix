package deprecated.oauth.token.storage

import deprecated.oauth.request.OAuthRequest
import deprecated.oauth.token.Token

interface RefreshTokenStorage {

    /**
     * Stores access request for the given refresh [token].
     */
    suspend fun createRefreshTokenSession(token: Token, request: OAuthRequest)

    /**
     * Retrieves request associated with refresh [token].
     */
    suspend fun getRefreshTokenSession(token: Token): OAuthRequest

    /**
     * Removes information related to the refresh [token].
     */
    suspend fun deleteRefreshTokenSession(token: Token)
}