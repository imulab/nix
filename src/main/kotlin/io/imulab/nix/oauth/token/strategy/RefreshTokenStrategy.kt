package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.oauth.request.OAuthRequest

/**
 * Strategy to generate and verify a refresh token.
 */
interface RefreshTokenStrategy {

    /**
     * Get the identifier of this token.
     */
    fun computeIdentifier(token: String): String

    /**
     * Generate a refresh token.
     */
    suspend fun generateToken(request: OAuthRequest): String

    /**
     * Verify a user presented token along with the current request.
     */
    suspend fun verifyToken(token: String, request: OAuthRequest)
}