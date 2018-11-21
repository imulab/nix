package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.token.Token

/**
 * Strategy for Open ID Connect id_token.
 */
interface IdTokenStrategy {

    /**
     * Generate a new Open ID Connect id_token.
     */
    suspend fun generateIdToken(request: OAuthRequest): Token
}