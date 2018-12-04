package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.request.OAuthRequest

interface RefreshTokenRepository {

    /**
     * Stores access request for the given refresh [token].
     */
    suspend fun createRefreshTokenSession(token: String, request: OAuthRequest)

    /**
     * Retrieves request associated with refresh [token].
     */
    suspend fun getRefreshTokenSession(token: String): OAuthRequest

    /**
     * Removes information related to the refresh [token].
     */
    suspend fun deleteRefreshTokenSession(token: String)

    /**
     * Removes the refresh token associated with request by [requestId].
     */
    suspend fun deleteRefreshTokenAssociatedWithRequest(requestId: String)
}