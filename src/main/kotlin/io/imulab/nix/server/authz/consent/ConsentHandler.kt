package io.imulab.nix.server.authz.consent

import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm

/**
 * Function to attempt acquire consent from user for the requested scopes and claims. Implementations may resort to
 * different approaches to obtain consent from user or recover a previous (still valid) consent. When unable to acquire
 * a consent, implementation may opt to raise an error (if it is convinced that no other implementation will succeed,
 * or that other implementation should not be allowed to make an attempt), or simply return to allow other implementations
 * to try.
 */
interface ConsentHandler {

    /**
     * Try to acquire user consent.
     *
     * @param form the request form containing request parameters from all sources
     * @param request the parsed open id connect request object from the request form, allowing access to session information and type safe parameters.
     * @param rawCall the original http request object, depending on the implementation or http provider selection.
     */
    suspend fun attemptAuthorize(form: OidcRequestForm, request: OidcAuthorizeRequest, rawCall: Any)
}