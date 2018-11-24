package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.token.Token

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