package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.oauth.request.OAuthRequest

/**
 * Strategy to generate and verify an access token.
 */
interface AccessTokenStrategy {

    /**
     * Get the identifier of this token.
     */
    fun computeIdentifier(token: String): String

    /**
     * Generate a new access token.
     */
    suspend fun generateToken(request: OAuthRequest): String

    /**
     * Verify a user presented access token along with the current request.
     */
    suspend fun verifyToken(token: String, request: OAuthRequest)
}