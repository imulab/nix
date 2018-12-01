package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthRequest

/**
 * Validate the parameter `state`. Its entropy must not be less than [OAuthContext.stateEntropy]. Because this is an
 * optional parameter, empty string is allowed.
 */
class StateValidator(private val oauthContext: OAuthContext) :
    OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val l = request.assertType<OAuthAuthorizeRequest>().state.length
        if (l in 1..(oauthContext.stateEntropy - 1))
            throw InvalidRequest.unmet("<state> length must not be less than ${oauthContext.stateEntropy}")
    }
}