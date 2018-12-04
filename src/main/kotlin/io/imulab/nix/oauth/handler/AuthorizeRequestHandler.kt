package io.imulab.nix.oauth.handler

import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse

/**
 * General interface for handling an authorization request.
 */
interface AuthorizeRequestHandler {

    /**
     * Handle an authorization request.
     */
    suspend fun handleAuthorizeRequest(request: OAuthAuthorizeRequest, response: AuthorizeEndpointResponse)
}