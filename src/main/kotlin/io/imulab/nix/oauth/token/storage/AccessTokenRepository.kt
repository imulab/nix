package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.request.OAuthRequest

interface AccessTokenRepository {

    /**
     * Stores access request for the given access [token].
     */
    suspend fun createAccessTokenSession(token: String, request: OAuthRequest)

    /**
     * Retrieves the request associated with the access [token].
     */
    suspend fun getAccessTokenSession(token: String): OAuthRequest

    /**
     * Removes information related to the access [token].
     */
    suspend fun deleteAccessTokenSession(token: String)
}