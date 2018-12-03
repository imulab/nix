package io.imulab.nix.oauth.authorize

import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse

/**
 * General interface for handling an authorization request.
 */
interface AuthorizeRequestHandler {

    /**
     * Handle an authorization request.
     */
    suspend fun handleRequest(request: OAuthAuthorizeRequest, response: AuthorizeEndpointResponse)
}