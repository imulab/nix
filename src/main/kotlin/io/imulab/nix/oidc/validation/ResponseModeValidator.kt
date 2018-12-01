package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.OidcParam
import io.imulab.nix.oidc.reserved.ResponseMode

/**
 * Validates parameter `response_mode`. The universe is `{query, fragment}`.
 * Because this parameter is optional, when used in the request, empty string is also allowed.
 */
object ResponseModeValidator : SpecDefinitionValidator,
    OAuthRequestValidation {
    override fun validate(value: String): String {
        return when (value) {
            ResponseMode.query, ResponseMode.fragment -> value
            else -> throw InvalidRequest.invalid(OidcParam.responseMode)
        }
    }

    override fun validate(request: OAuthRequest) {
        val rm = request.assertType<OidcAuthorizeRequest>().responseMode
        if (rm.isNotEmpty())
            validate(rm)
    }
}