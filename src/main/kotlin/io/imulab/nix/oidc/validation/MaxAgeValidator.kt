package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.OidcParam

/**
 * Validates the `max_age` parameter. It must not be less than 0.
 */
object MaxAgeValidator : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        if (request.assertType<OidcAuthorizeRequest>().maxAge < 0)
            throw InvalidRequest.invalid(OidcParam.maxAge)
    }
}