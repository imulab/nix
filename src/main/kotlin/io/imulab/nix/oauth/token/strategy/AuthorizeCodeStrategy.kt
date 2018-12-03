package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.oauth.request.OAuthAuthorizeRequest

/**
 * Strategy to generate and validate an authorization code.
 */
interface AuthorizeCodeStrategy {

    /**
     * Get the identifier of this code.
     */
    fun computeIdentifier(code: String): String

    /**
     * Generate an authorization code.
     */
    suspend fun generateCode(request: OAuthAuthorizeRequest): String

    /**
     * Verify a user presented authorization code, along with the current request.
     */
    suspend fun verifyCode(code: String, request: OAuthAuthorizeRequest)
}