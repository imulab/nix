package io.imulab.nix.server.authz.authn

import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm

/**
 * Function to attempt acquiring authentication information. Implementations may resort to different approaches to
 * assert the authentication status of the current request. When an authentication status can be confirmed, the
 * [OidcAuthorizeRequest.session] should be updated to include `subject` and `auth_time` information. When unable
 * to secure an authentication status, implementation may choose to either raise an error (if it is convinced that
 * no other implementation can confirm authentication or that other implementation should not be allowed to obtain
 * authentication provided the error) or simply return to let other implementation try.
 */
interface AuthenticationHandler {

    /**
     * Try to obtain authentication status.
     *
     * @param form the request form containing request parameters from all sources
     * @param request the parsed open id connect request object from the request form, allowing access to session information and type safe parameters.
     * @param rawCall the original http request object, depending on the implementation or http provider selection.
     */
    suspend fun attemptAuthenticate(form: OidcRequestForm, request: OidcAuthorizeRequest, rawCall: Any)
}