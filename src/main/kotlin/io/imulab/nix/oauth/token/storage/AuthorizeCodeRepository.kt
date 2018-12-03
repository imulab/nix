package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.request.OAuthRequest

interface AuthorizeCodeRepository {

    /**
     * Stores authorization request for given authorize code.
     */
    suspend fun createAuthorizeCodeSession(code: String, request: OAuthRequest)

    /**
     * Retrieves authorization request for given [code]. Implementations
     * should throw exception if the [code] has already been invalidated.
     */
    suspend fun getAuthorizeCodeSession(code: String): OAuthRequest

    /**
     * Invalidates the stored session identified by [code]. It should be called when the [code] is used.
     */
    suspend fun invalidateAuthorizeCodeSession(code: String)
}