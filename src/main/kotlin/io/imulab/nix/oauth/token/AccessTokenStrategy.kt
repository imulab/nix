package io.imulab.nix.oauth.token

import io.imulab.nix.oauth.request.OAuthRequest

/**
 * Strategy to generate and verify an access token.
 */
interface AccessTokenStrategy {

    /**
     * Generate a new access token.
     */
    suspend fun generateToken(request: OAuthRequest): String

    /**
     * Verify a user presented access token along with the current request.
     */
    suspend fun verifyToken(token: String, request: OAuthRequest)
}