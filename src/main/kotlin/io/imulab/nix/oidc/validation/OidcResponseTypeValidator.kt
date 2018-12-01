package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.UnauthorizedClient
import io.imulab.nix.oauth.error.UnsupportedResponseType
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oauth.validation.OAuthResponseTypeValidator
import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.ResponseType
import java.lang.Exception

/**
 * Validates the set relation: `response_type = {code, token}`.
 * When in the context of a request, it must be registered/allowed by the client.
 */
object OidcResponseTypeValidator : SpecDefinitionValidator,
    OAuthRequestValidation {
    override fun validate(value: String): String {
        try {
            return OAuthResponseTypeValidator.validate(value)
        } catch (e: Exception) {
            if (value == ResponseType.idToken)
                return value
            throw UnsupportedResponseType.unsupported(value)
        }
    }

    override fun validate(request: OAuthRequest) {
        val ar = request.assertType<OidcAuthorizeRequest>()
        ar.responseTypes.forEach {
            validate(it)
            if (!ar.client.responseTypes.contains(it))
                throw UnauthorizedClient.forbiddenResponseType(it)
        }
    }
}