package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.Display
import io.imulab.nix.oidc.reserved.OidcParam

/**
 * Validates the `display` parameter. The universe if `{page, popup, touch, wap}`. Because this parameter is optional,
 * when used in a request, empty string is also allowed.
 */
object DisplayValidator : SpecDefinitionValidator,
    OAuthRequestValidation {
    override fun validate(value: String): String {
        return when(value) {
            Display.page, Display.popup, Display.touch, Display.wap -> value
            else -> throw InvalidRequest.invalid(OidcParam.display)
        }
    }

    override fun validate(request: OAuthRequest) {
        val d = request.assertType<OidcAuthorizeRequest>().display
        if (d.isNotEmpty())
            validate(d)
    }
}