package io.imulab.nix.oidc.token

import io.imulab.nix.oauth.request.OAuthRequest

/**
 * Strategy to generate an id token.
 */
interface IdTokenStrategy {

    /**
     * Generate a new id token.
     */
    suspend fun generateToken(request: OAuthRequest): String
}